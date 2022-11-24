/*
    Abbreviations used:
    len: length
    desc: Descriptor

    http://www.osta.org/specs/pdf/udf260.pdf - Section 1.3.4
*/

use bitflags::bitflags;
use nom_derive::Nom;
use nom_derive::Parse;

pub type LSN = u32; // Logical Sector Number

#[derive(Nom, Clone)]
#[nom(LittleEndian)]
pub struct ExtentAD {
    pub len: u32,
    pub loc: LSN,
}

#[derive(Nom, PartialEq, Debug, Clone)]
#[nom(LittleEndian)]
#[repr(u16)]
pub enum TagID {
    UNK = 0,
    PVD,
    AVD,
    VD,
    IUVD,
    PD,
    LVD,
    USD,
    TD,
    LVID,
}

#[derive(Nom, Clone)]
#[nom(LittleEndian)]
pub struct Tag {
    pub tag_id: TagID,
    pub version: u16,
    pub checksum: u8,
    _res: u8,
    pub serial: u16,
    pub desc_crc: u16,
    pub desc_crc_len: u16,
    pub tag_loc: LSN,
}

pub struct NSR {
    pub struct_type: u8,
    pub ident: [u8; 5],
    pub version: u8,
    _res: u8,
    _data: [u8; 2040],
}

#[derive(Nom, Clone)]
#[nom(LittleEndian)]
pub struct CharSpec {
    pub cs_type: u8,
    pub cs_info: [u8; 63],
}

/* bitflags! {
    struct RegIDFlags: u8 {
        const DIRTY = 0b00000001;
        const PROTECTED = 0b00000010;
    }
} */

#[derive(Nom, Clone, Debug)]
#[nom(LittleEndian)]
pub struct RegID {
    pub flags: u8,
    pub ident: [u8; 23],
    pub ident_suffix: [u8; 8],
}

#[derive(Nom, Clone)]
#[nom(LittleEndian)]
pub struct Timestamp {
    pub type_tz: u16,
    pub year: i16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub centisecond: u8,
    pub centims: u8,
    pub microsecond: u8,
}

pub struct BD {
    pub struct_type: u8, // should always be 0
    pub ident: [u8; 5],
    pub version: u8, // should always be 1
    _res: u8,
    pub arch: RegID,
    pub boot_ident: RegID,
    pub boot_ext_loc: LSN,
    pub boot_ext_len: u32,
    pub load_addr: u64,
    pub start_addr: u64,
    pub desc_cdate: Timestamp,
    pub flags: u16,
    _res2: [u8; 32],
    pub boot_raw: [u8; 1906],
}

#[derive(Nom, Clone)]
#[nom(LittleEndian)]
pub struct PVD {
    #[nom(Verify = "tag.tag_id == TagID::PVD")]
    pub tag: Tag,
    pub vds_num: u32,
    pub pvd_num: u32,
    pub vol_ident: [u8; 32],
    pub vol_seq_num: u16,
    pub max_vol_seq_num: u16,
    pub ic_level: u16,
    pub max_ic_level: u16,
    pub charset: u32,
    pub max_charset: u32,
    pub vol_set_ident: [u8; 128],
    pub desc_charset: CharSpec,
    pub expl_charset: CharSpec,
    pub vol_abstract: ExtentAD,
    pub vol_copyright: ExtentAD,
    pub appid: RegID,
    pub record_time: Timestamp,
    pub impl_id: RegID,
    pub impl_use: [u8; 64],
    pub predec_vds: LSN,
    pub flags: u16,
    _res: [u8; 22],
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct AVD {
    #[nom(Verify = "tag.tag_id == TagID::AVD")]
    pub tag: Tag,
    pub main_vds: ExtentAD,
    pub reserve_vds: ExtentAD,
    _res: [u8; 480],
}

pub struct VD {
    pub tag: Tag,
    pub vds_num: u32,
    pub next_vds: ExtentAD,
    _res: [u8; 484],
}

pub struct IUVD {
    pub tag: Tag,
    pub vds_num: u32,
    pub impl_id: RegID,
    pub impl_use: [u8; 460],
}

#[derive(Nom, Clone)]
#[nom(LittleEndian)]
pub struct PD {
    #[nom(Verify = "tag.tag_id == TagID::PD")]
    pub tag: Tag,
    pub vds_num: u32,
    pub part_flags: u16,
    pub part_num: u16,
    pub part_cont: RegID,
    pub part_cont_use: [u8; 128],
    pub atype: u32,
    pub part_start: LSN,
    pub part_len: u32,
    pub impl_ident: RegID,
    pub impl_use: [u8; 128],
    _res: [u8; 156],
}

#[derive(Nom, Debug)]
#[nom(LittleEndian)]
pub struct PMType1 {
    #[nom(Verify = "*len == 6")]
    pub len: u8,
    pub vol_seq_num: u16,
    pub part_num: u16,
}

#[derive(Nom, Debug)]
#[nom(LittleEndian)]
pub struct PMType2 {
    #[nom(Verify = "*len == 64")]
    pub len: u8,
    _res: [u8; 2],
    pub part_ident: RegID,
    pub vol_seq_nr: u16,
    pub part_num: u16,
    pub meta_file_loc: u32,
    pub meta_mirror_loc: u32,
    pub meta_bmp_loc: u32,
    pub alloc_usize: u32,
    pub align_usize: u16,
    pub flags: u8,
    _res2: [u8; 5],
}

#[derive(Nom, Debug)]
#[nom(LittleEndian, Selector = "u8")]
pub enum PartMapType {
    #[nom(Selector = "0")]
    UNK {
        len: u8,
        #[nom(Count = "len as usize - 2")]
        data: Vec<u8>,
    },
    #[nom(Selector = "1")]
    Type1(PMType1),
    #[nom(Selector = "2")]
    Type2(PMType2),
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct PartMap {
    _pm_type: u8,
    #[nom(Parse = "{ |i| PartMapType::parse(i, _pm_type) }")]
    pub part_map: PartMapType,
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct LVD {
    #[nom(Verify = "tag.tag_id == TagID::LVD")]
    pub tag: Tag,
    pub vds_num: u32,
    pub desc_charset: CharSpec,
    pub lvid: [u8; 128],
    #[nom(Verify = "*lbs as u64 == crate::BLOCKSIZE")]
    pub lbs: u32,
    pub domain_id: RegID,
    pub lv_contents_use: [u8; 16],
    pub map_table_len: u32,
    pub num_part_maps: u32,
    pub impl_ident: RegID,
    pub impl_use: [u8; 128],
    pub integr_seq_ext: ExtentAD,
    #[nom(Count = "num_part_maps")]
    pub part_maps: Vec<PartMap>,
}

pub struct USD {
    pub tag: Tag,
    pub vds_num: u32,
    pub num_alloc_desc: u32,
    pub alloc_descs: Vec<ExtentAD>, // of length num_alloc_desc
}

#[derive(Nom)]
#[nom(LittleEndian)]
pub struct TD {
    #[nom(Verify = "tag.tag_id == TagID::TD")]
    pub tag: Tag,
    _res: [u8; 496],
}

pub struct LVID {
    pub tag: Tag,
    pub rec_time: Timestamp,
    pub integ_type: u8,
    pub next_integ_ext: ExtentAD,
    pub lvc_use: [u8; 32],
    pub num_part: u32,
    pub len_impl_use: u32,
    pub free_space_tbl: Vec<u32>, // of length num_part
    pub size_tbl: Vec<u32>,       // of length num_part
    pub impl_use: Vec<u8>,        // of length len_impl_use
}
