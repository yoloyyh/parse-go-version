use std::env;
use std::fs::File;
use std::io::{self, Read};
use goblin::elf::Elf;
use byteorder::{ByteOrder, LittleEndian, BigEndian};
use regex::Regex;
use std::io::Seek;
use std::io::SeekFrom;

const MAGIC: &[u8] = b"\xff Go buildinf:";
const EXPECTED_MAGIC_LEN: usize = 14;
const FLAGS_OFFSET: usize = 15;

const BUILDINFO_ALIGN: usize = 16;
const BUILDINFO_HEADER_SIZE: usize = 32;
const MAX_VAR_INT_LEN64: usize = 10;

const FLAGS_VERSION_MASK: u8  = 0x2;
const FLAGS_ENDIAN_BIG: u8   = 0x1;


fn parse_version(version: &String) -> &str {
     let re = Regex::new(r"^go(\d+\.\d+)(?:\.\d+)?").unwrap();

     // 使用正则进行匹配
     if let Some(captures) = re.captures(version) {
         if let Some(version_number) = captures.get(1) {
             let extracted_version = version_number.as_str();
             return extracted_version;
         }
     }
     return "";
}

fn uvarint(buf: &[u8]) -> (u64, i32) {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_VAR_INT_LEN64 {
            return (0, -(i as i32 + 1)); // overflow
        }
        if b < 0x80 {
            if i == MAX_VAR_INT_LEN64 - 1 && b > 1 {
                return (0, -(i as i32 + 1)); // overflow
            }
            return (x | (b as u64) << s, (i + 1) as i32);
        }
        x |= ((b & 0x7F) as u64) << s;
        s += 7;
    }
    return (0, 0);
}

fn read_ptr(b: &[u8], ptr_size: usize, is_little_endian: bool) -> Option<u64> {
    match ptr_size {
        4 => {
            if is_little_endian{
                return Some(u64::from(LittleEndian::read_u32(b)));
            } else {
                return Some(u64::from(BigEndian::read_u32(b)));
            }
        }
        8 => {
            if is_little_endian{
                return Some(u64::from(LittleEndian::read_u64(b)));
            } else {
                return Some(u64::from(BigEndian::read_u64(b)));
            }
        }
        _ => None,
    }
}

fn read_data_at_address(mut file: &File, elf: &Elf, address: u64, size: usize) -> Option<Vec<u8>> {
    let section = match elf.section_headers.iter().find(|section| {
        section.sh_addr <= address && address < section.sh_addr + section.sh_size
    }) {
        Some(section) => section,
        None => return None,
    };
    
    let offset = (address - section.sh_addr) as u64;
    if let Err(_) = file.seek(SeekFrom::Start(section.sh_offset + offset)) {
        return None;
    }
    
    let mut buffer = vec![0u8; size];
    if let Err(_) = file.read_exact(&mut buffer) {
        return None;
    }
    
    Some(buffer)
}

fn find_by_section(elf: &Elf, buffer:&Vec<u8>, file: &File) -> String {
    let mut version: String = String::new();
    
    
    // find .go.buildinfo 
    if let Some(go_buildinfo_section) = elf.section_headers.iter().find(|section| {
        if let Some(sect_name) = elf.shdr_strtab.get_at(section.sh_name) {
            sect_name == ".go.buildinfo"
        } else {
            false
        }
    }) {
         // read ".go.buildinfo" section data
        let buildinfo_data = &buffer[go_buildinfo_section.sh_offset as usize
        ..(go_buildinfo_section.sh_offset + go_buildinfo_section.sh_size) as usize];

        // check Magic
        let magic_header = &buildinfo_data[0..EXPECTED_MAGIC_LEN];
        if magic_header == MAGIC {
            let flag = buildinfo_data[FLAGS_OFFSET];
            // Since 1.18, the flags version bit is flagsVersionInl. In this case,
            // the header is followed by the string contents inline as
            // length-prefixed (as varint) string contents. First is the version
            // string, followed immediately by the modinfo string.
            if flag & FLAGS_VERSION_MASK == FLAGS_VERSION_MASK {
                let version_u8 = match read_data_at_address(&file, &elf, go_buildinfo_section.sh_addr + BUILDINFO_HEADER_SIZE  as u64, MAX_VAR_INT_LEN64) {
                    Some(data) => data,
                    None => {
                        eprintln!("Failed to read version data");
                        return version;
                    }
                };
                let len = uvarint(&version_u8).0;

                version = String::from_utf8_lossy(&buildinfo_data[BUILDINFO_HEADER_SIZE + 1 ..BUILDINFO_HEADER_SIZE + 1 + len as usize]).to_string();
                println!("version: {}", version);

            } else {
                // go version < 1.18
                let ptr_size = buildinfo_data[EXPECTED_MAGIC_LEN] as usize;
                let big_endian = flag & FLAGS_VERSION_MASK == FLAGS_ENDIAN_BIG;
                // Read the version address and length based on endianness
                if let Some(version_address) = read_ptr(&buildinfo_data[BUILDINFO_ALIGN as usize..(BUILDINFO_ALIGN + ptr_size) as usize], ptr_size, !big_endian) {
                    if let Some(version_address_ptr) = read_data_at_address(&file, &elf, version_address, ptr_size * 2) {
                        let version_address_ptr_u64 = match read_ptr(&version_address_ptr[0..ptr_size], ptr_size, !big_endian) {
                            Some(ptr) => ptr,
                            None => {
                                eprintln!("Failed to read version address pointer");
                                return version;
                            }
                        };
                        let version_len_ptr_u64 = match read_ptr(&version_address_ptr[ptr_size..ptr_size * 2], ptr_size, !big_endian) {
                            Some(ptr) => ptr,
                            None => {
                                eprintln!("Failed to read version length pointer");
                                return version;
                            }
                        };
                        let version_u8 = match read_data_at_address(&file, &elf, version_address_ptr_u64, version_len_ptr_u64 as usize) {
                            Some(data) => data,
                            None => {
                                eprintln!("Failed to read version data");
                                return version;
                            }
                        };
                
                        version = String::from_utf8_lossy(&version_u8).to_string();
                        println!("version: {}", version);
                    }
                }
            }
        }
     }
    version
}

pub fn read_string_from_address(mut file: File, address: u64, length: u64) -> io::Result<String> {

    file.seek(SeekFrom::Start(address))?;

    let mut version_bytes = vec![0; length as usize];
    file.read_exact(&mut version_bytes)?;

    let version = String::from_utf8_lossy(&version_bytes).to_string();
    Ok(version)
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <elf-file>", args[0]);
        return Ok(());
    }
    let path = &args[1];

    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    // parse elf
    let elf = match Elf::parse(&buffer) {
        Ok(elf) => elf,
        Err(err) => {
            eprintln!("Failed to parse ELF file: {}", err);
            return  Ok(());
        }
    };
    
    let version = find_by_section(&elf, &buffer, &file);
    if version.is_empty() {
        println!("get go version by elf failed");
        
    } else {
       println!("get go version: {}", parse_version(&version));
    }
    
    Ok(())
}


