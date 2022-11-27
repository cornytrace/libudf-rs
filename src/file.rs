use bitfield::BitRange;
use nom::number::complete::*;
use nom_derive::Nom;
use nom_derive::Parse;

use crate::volume::DString;
use crate::volume::{CharSpec, RegID, Timestamp};

pub type LBN = u32;

#[derive(Nom, Debug)]
#[nom(LittleEndian)]
pub struct LBAddr {
    pub lbn: LBN,
    pub part_ref_nr: u16,
}

#[derive(Debug)]
pub struct ShortAD {
    pub len: u32,
    pub pos: LBN,
    pub ty: u8,
}
impl ShortAD {
    pub fn parse_le<'nom>(i: &'nom [u8]) -> nom::IResult<&'nom [u8], Self> {
        let (i, len) = u32::parse_le(i)?;
        let (i, pos) = <_>::parse_le(i)?;
        let ty: u8 = len.bit_range(31, 30);
        let len = len.bit_range(29, 0);
        Ok((i, Self { len, pos, ty }))
    }
}

#[derive(Debug)]
pub struct LongAD {
    pub len: u32,
    pub loc: LBAddr,
    pub impl_use: [u8; 6],
    pub ty: u8,
}
impl LongAD {
    pub fn parse_le<'nom>(i: &'nom [u8]) -> nom::IResult<&'nom [u8], Self> {
        let (i, len) = le_u32(i)?;
        let (i, loc) = <_>::parse_le(i)?;
        let (i, impl_use) = <_>::parse_le(i)?;
        let ty: u8 = len.bit_range(31, 30);
        let len = len.bit_range(29, 0);

        Ok((
            i,
            Self {
                len,
                loc,
                impl_use,
                ty,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ExtAD {
    pub len: u32,
    pub rec_len: u32,
    pub info_len: u32,
    pub ext_loc: LBAddr,
    pub impl_use: [u8; 2],
    pub len_ty: u8,
    pub rec_len_ty: u8,
}
impl ExtAD {
    pub fn parse_le<'nom>(i: &'nom [u8]) -> nom::IResult<&'nom [u8], Self> {
        let (i, len) = le_u32(i)?;
        let (i, rec_len) = le_u32(i)?;
        let (i, info_len) = le_u32(i)?;
        let (i, ext_loc) = <_>::parse_le(i)?;
        let (i, impl_use) = <_>::parse_le(i)?;
        let len_ty: u8 = len.bit_range(31, 30);
        let len = len.bit_range(29, 0);
        let rec_len_ty: u8 = rec_len.bit_range(31, 30);
        let rec_len = rec_len.bit_range(29, 0);
        Ok((
            i,
            Self {
                len,
                rec_len,
                info_len,
                ext_loc,
                impl_use,
                len_ty,
                rec_len_ty,
            },
        ))
    }
}

#[derive(Clone)]
#[repr(u8)]
pub enum AllocType {
    SHORT = 0,
    LONG,
    EXTENDED,
}

#[derive(Nom, Debug)]
#[nom(LittleEndian, Selector = "AllocType")]
pub enum AllocDesc {
    #[nom(Selector = "AllocType::SHORT")]
    SHORT(ShortAD),
    #[nom(Selector = "AllocType::LONG")]
    LONG(LongAD),
    #[nom(Selector = "AllocType::EXTENDED")]
    EXTENDED(ExtAD),
}
impl From<ShortAD> for AllocDesc {
    fn from(value: ShortAD) -> Self {
        AllocDesc::SHORT(value)
    }
}
impl From<LongAD> for AllocDesc {
    fn from(value: LongAD) -> Self {
        AllocDesc::LONG(value)
    }
}
impl From<ExtAD> for AllocDesc {
    fn from(value: ExtAD) -> Self {
        AllocDesc::EXTENDED(value)
    }
}

#[derive(Nom, PartialEq, Debug)]
#[nom(LittleEndian)]
#[repr(u16)]
pub enum FileTagID {
    TD = 8,
    FSD = 256,
    FID = 257,
    AED = 258,
    IE = 259,
    TE = 260,
    FE = 261,
    EAHD = 262,
    USE = 263,
    SBD = 264,
    PIE = 265,
    EFE = 266,
}

#[derive(Nom, Debug)]
#[nom(LittleEndian)]
pub struct FileTag {
    pub tag_id: FileTagID,
    pub version: u16,
    pub checksum: u8,
    _res: u8,
    pub serial: u16,
    pub desc_crc: u16,
    pub desc_crc_len: u16,
    pub tag_loc: LBN,
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct FSD {
    #[nom(Verify = "tag.tag_id == FileTagID::FSD")]
    pub tag: FileTag,
    pub rec_time: Timestamp,
    pub interch_lvl: u16,
    pub max_interch_lvl: u16,
    pub charset_list: u32,
    pub max_charset_list: u32,
    pub fs_num: u32,
    pub fsd_num: u32,
    pub lv_id_charset: CharSpec,
    pub lv_id: DString<128>,
    pub fs_charset: CharSpec,
    pub fs_id: DString<32>,
    pub copyright_id: DString<32>,
    pub af_id: DString<32>,
    pub root_dir_icb: LongAD,
    pub domain_id: RegID,
    pub next_extent: LongAD,
    pub ssd_icb: LongAD,
    _res: [u8; 32],
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct FSDTD {
    pub tag: FileTag,
    _res: [u8; 496],
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct PHD {
    pub us_tbl: ShortAD,
    pub us_bmp: ShortAD,
    pub part_it: ShortAD,
    pub free_spc_tbl: ShortAD,
    pub free_spc_bmp: ShortAD,
    _res: [u8; 88],
}

#[derive(Nom, Debug)]
#[nom(LittleEndian)]
pub struct FID {
    #[nom(Verify = "tag.tag_id == FileTagID::FID")]
    pub tag: FileTag,
    pub version: u16,
    pub file_bits: u8,
    pub fid_len: u8,
    pub icb: LongAD,
    pub impl_len: u16,
    #[nom(Count = "impl_len")]
    pub impl_use: Vec<u8>,
    #[nom(Count = "fid_len")]
    pub fid: Vec<u8>,
    #[nom(
        Count = "4 * ((fid_len as usize+impl_len as usize+38+3)/4)-(fid_len as usize+impl_len as usize+38)"
    )]
    _padding: Vec<u8>,
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct AED {
    #[nom(Verify = "tag.tag_id == FileTagID::AED")]
    pub tag: FileTag,
    pub prev_aed: LBN,
    pub ad_len: u32,
}

#[derive(Nom, Copy, Clone, Debug)]
#[nom(LittleEndian)]
#[repr(u8)]
pub enum FileType {
    UNK = 0,
    USE,
    PIE,
    IE,
    DIR,
    BYTES,
    BLOCKDEV,
    CHARDEV,
    EXTATTR,
    FIFO,
    SOCK,
    TE,
    SYMLINK,
    STREAMDIR,
    METAMAIN = 250,
    METAMIRROR,
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct ICBFlags {
    bits: u16,
}
impl ICBFlags {
    pub fn get_alloc_type(&self) -> Result<AllocType, &str> {
        let ty: u8 = self.bits.bit_range(3, 0);
        match ty {
            0 => Ok(AllocType::SHORT),
            1 => Ok(AllocType::LONG),
            2 => Ok(AllocType::EXTENDED),
            _ => Err("unknown alloc type."),
        }
    }
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct ICBTag {
    pub num_prior_entries: u32,
    pub strategy: u16, // TODO: enum
    pub strat_param: [u8; 2],
    pub max_num_entries: u16,
    _res: u8,
    pub file_type: FileType,
    pub parent_icb: LBAddr,
    pub flags: ICBFlags, // TODO: functions
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct FileEntry {
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub file_link_count: u16,
    pub record_format: u8,
    pub record_disp_attrib: u8,
    pub record_len: u32,
    pub info_len: u64,
    pub num_lb_recorded: u64,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub attrtime: Timestamp,
    pub checkpoint: u32,
    pub ea_icb: LongAD,
    pub impl_ident: RegID,
    pub unique_id: u64,
    _ea_len: u32,
    _ad_len: u32,
    #[nom(Count = "_ea_len")]
    pub ex_attrs: Vec<u8>,
    #[nom(Count = "_ad_len")]
    pub alloc_descs: Vec<u8>,
}

pub enum ICBBody {
    Indirect(LongAD),
    Terminal(),
    File(FileEntry),
}
impl ICBBody {
    pub fn parse_le<'nom>(i: &'nom [u8], selector: FileType) -> nom::IResult<&'nom [u8], Self> {
        match selector {
            FileType::TE => return Ok((i, Self::Terminal())),
            FileType::UNK
            | FileType::DIR
            | FileType::BYTES
            | FileType::BLOCKDEV
            | FileType::CHARDEV
            | FileType::EXTATTR
            | FileType::FIFO
            | FileType::SOCK
            | FileType::METAMAIN
            | FileType::METAMIRROR => return FileEntry::parse(i).map(|e| (e.0, Self::File(e.1))),
            _ => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    i,
                    nom::error::ErrorKind::Fail,
                )))
            }
        }
    }
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct ICB {
    pub tag: FileTag,
    pub icb_tag: ICBTag,
    #[nom(Parse = "{ |i| ICBBody::parse_le(i, icb_tag.file_type) }")]
    pub body: ICBBody,
}
impl ICB {
    pub fn get_alloc_descs(&self) -> Vec<AllocDesc> {
        let mut vec = Vec::new();
        let ty = self.icb_tag.flags.get_alloc_type().unwrap();
        if let ICBBody::File(file) = &self.body {
            let mut desc = AllocDesc::parse(&file.alloc_descs, ty.clone());
            loop {
                if let Ok(res) = desc {
                    vec.push(res.1);
                    desc = AllocDesc::parse(&res.0, ty.clone());
                } else {
                    break;
                }
            }
        }
        vec
    }
}
