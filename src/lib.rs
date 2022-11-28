pub mod file;
pub mod parser;
pub mod volume;

use log::{info, warn};
use nom_derive::Parse;
use std::{
    error::Error,
    io::{Read, Seek, SeekFrom},
};

use file::*;
use volume::*;

pub const BLOCKSIZE: u64 = 2048;

pub struct UDF<IO: Read + Seek> {
    io: Box<IO>,
    pub primary_vol_desc: PVD,
    pub part_desc: PD,
    pub logical_vol_desc: LVD,
    meta_file_offset: Option<u32>,
}

impl<IO: Read + Seek> UDF<IO> {
    pub fn new(mut io: IO) -> Result<Self, Box<dyn Error>> {
        let mut buf: [u8; BLOCKSIZE as usize] = [0; BLOCKSIZE as usize];

        io.seek(SeekFrom::Start(256 * BLOCKSIZE))?;
        io.read(&mut buf)?;

        let avd = AVD::parse(&buf).or(Err("error parsing AVD"))?.1;
        io.seek(SeekFrom::Start(avd.main_vds.loc as u64 * BLOCKSIZE))?;

        io.read(&mut buf)?;

        let mut o_pvd: Option<PVD> = None;
        let mut o_pd: Option<PD> = None;
        let mut o_lvd: Option<LVD> = None;

        let vds_start: LSN = avd.main_vds.loc;
        let vds_end: LSN = vds_start + avd.main_vds.len;

        for n in vds_start..vds_end {
            io.seek(SeekFrom::Start(n as u64 * BLOCKSIZE)).unwrap();
            io.read(&mut buf).unwrap();
            let tag = Tag::parse(&buf).or(Err("error parsing VDS tag"))?.1;

            if tag.tag_id != TagID::UNK {
                info!("Found descriptor of type: {:?}", tag.tag_id);
            }
            match tag.tag_id {
                TagID::TD => {
                    break;
                }
                TagID::VD => {
                    break;
                }
                TagID::PVD => {
                    let pvd = PVD::parse(&buf).unwrap().1;
                    info!("Volume Identifier: {}", pvd.vol_ident);
                    o_pvd = Some(pvd);
                }
                TagID::PD => {
                    let pd = PD::parse(&buf).or(Err("error parsing PD."))?.1;
                    let ident = std::str::from_utf8(&pd.part_cont.ident)
                        .unwrap()
                        .trim_matches('\0');
                    info!("Found partition {} of type {}", pd.part_num, ident);
                    match ident {
                        "+NSR02" | "+NSR03" => {
                            //let phd = PHD::parse(&pd.impl_use).unwrap().1;
                        }
                        _ => {
                            warn!("Unknown partition type: {}", ident);
                        }
                    }
                    o_pd = Some(pd);
                }
                TagID::LVD => {
                    let lvd = LVD::parse(&buf).unwrap().1;
                    info!("Found logical volume: {}", lvd.lvid);
                    o_lvd = Some(lvd);
                }
                _ => {}
            }
        }

        let pvd = o_pvd.ok_or("no primary volume descriptor found")?;
        let pd = o_pd.ok_or("no partition descriptor found")?;
        let lvd = o_lvd.ok_or("no local volume descriptor found")?;

        // Search for metadata offset of FSD
        let mut metadata_offset: Option<u32> = None;
        {
            let mut meta_file_loc: Option<u32> = None;
            for part_map in &lvd.part_maps {
                match &part_map.part_map {
                    PartMapType::Type2(part) => {
                        info!("Found metadata partition");
                        meta_file_loc = Some(part.meta_file_loc);
                    }
                    _ => {}
                }
            }
            if let Some(meta_file_loc) = meta_file_loc {
                io.seek(SeekFrom::Start(
                    (pd.part_start + meta_file_loc) as u64 * BLOCKSIZE,
                ))?;
                io.read(&mut buf)?;
                let meta_file = ICB::parse(&buf).unwrap().1;
                let alloc_descs = meta_file.get_alloc_descs();
                if let Some(desc) = alloc_descs.get(0) {
                    match desc {
                        AllocDesc::SHORT(ad) => metadata_offset = Some(ad.pos),
                        AllocDesc::LONG(ad) => metadata_offset = Some(ad.loc.lbn),
                        AllocDesc::EXTENDED(ad) => metadata_offset = Some(ad.ext_loc.lbn),
                    }
                }
            }
        }

        Ok(Self {
            io: Box::new(io),
            primary_vol_desc: pvd,
            part_desc: pd,
            logical_vol_desc: lvd,
            meta_file_offset: metadata_offset,
        })
    }

    pub fn get_root_dir(&mut self) -> Result<ICB, Box<dyn Error>> {
        let fsd_ext = LongAD::parse_le(&self.logical_vol_desc.lv_contents_use)
            .or(Err("error parsing FSD pointer."))?
            .1;
        let mut fsd_loc = self.part_desc.part_start + fsd_ext.loc.lbn;
        if let Some(meta_offset) = self.meta_file_offset {
            fsd_loc += meta_offset;
        }
        let mut buf: [u8; BLOCKSIZE as usize] = [0; BLOCKSIZE as usize];
        self.io.seek(SeekFrom::Start(fsd_loc as u64 * BLOCKSIZE))?;
        self.io.read(&mut buf)?;
        let fsd = FSD::parse(&buf).or(Err("error parsing FSD"))?.1;
        let mut icb_loc = self.part_desc.part_start + fsd.root_dir_icb.loc.lbn;
        if let Some(meta_offset) = self.meta_file_offset {
            icb_loc += meta_offset;
        }
        self.io.seek(SeekFrom::Start(icb_loc as u64 * BLOCKSIZE))?;
        self.io.read(&mut buf)?;
        let root_entry = ICB::parse(&buf).or(Err("error parsing root ICB"))?.1;

        let root_ad = root_entry.get_alloc_descs();
        if root_ad.len() > 1 {
            Err("multiple allocation descriptors for one ICB not supported yet")?;
        }
        Ok(root_entry)
    }

    pub fn alloc_desc_to_offset_len(&self, ad: &AllocDesc) -> (u32, u32) {
        let mut loc: u32;
        let len: u32;
        match ad {
            AllocDesc::SHORT(x) => {
                loc = x.pos;
                len = x.len;
            }
            AllocDesc::LONG(x) => {
                loc = x.loc.lbn;
                len = x.len;
            }
            AllocDesc::EXTENDED(x) => {
                loc = x.ext_loc.lbn;
                len = x.len;
            }
        }
        loc += self.part_desc.part_start;
        if let Some(meta_offset) = self.meta_file_offset {
            loc += meta_offset;
        }
        (loc * BLOCKSIZE as u32, len)
    }

    pub fn read_into_buf(&mut self, ad: &AllocDesc) -> Result<Vec<u8>, Box<dyn Error>> {
        let (loc, len) = self.alloc_desc_to_offset_len(ad);
        let mut buf = vec![0; len as _];
        self.io.seek(SeekFrom::Start(loc as _))?;
        self.io.read_exact(&mut buf)?;
        return Ok(buf);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::BufReader};

    use super::*;

    fn init_logger() {
        let _ = env_logger::builder()
            // Include all events in tests
            .filter_level(log::LevelFilter::max())
            // Ensure events are captured by `cargo test`
            .is_test(true)
            // Ignore errors initializing the logger if tests race to configure it
            .try_init();
    }

    #[test]
    fn it_works() -> Result<(), Box<dyn Error>> {
        init_logger();
        let file = File::open("./tests/test.iso").unwrap();
        let mut file = BufReader::new(file);
        let mut udf = UDF::new(&mut file)?;
        let root_icb = udf.get_root_dir()?;
        let c = root_icb.get_children(&mut udf);
        let lic_udf = c.get("LICENSE.md").unwrap().get_content(&mut udf);
        assert_eq!(lic_udf.as_slice(), include_bytes!("../LICENSE.md"));
        Ok(())
    }
}
