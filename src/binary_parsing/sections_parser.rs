use super::bin_reader::BinReader;

// WebAssembly consists of 11 sections. Our Section struct will hold the data for each. 
#[derive(Clone)]
pub struct Section {
    pub id: u8,
    pub size: u32,
    pub data: Vec<u8>,
}

pub struct SectionsParser;

impl SectionsParser {
    pub fn parse(mut reader: BinReader) -> Vec<Section> {
        let mut sections = Vec::new();

        // Read the wasm magic header to verify the binary is a WebAssembly binary.
        let magic = reader.read_bytes(4).expect("Failed to read WASM magic number");
        if magic != [0x00, 0x61, 0x73, 0x6D] {
            panic!("Invalid WASM magic number detected.");
        }

        // Read the version bytes header. 
        let version = reader.read_bytes(4).expect("Failed to read WASM version");
        if version != [0x01, 0x00, 0x00, 0x00] {
            eprintln!("WasmCrack expects version 1.0, but got {:?}. Instructions and features from later versions are not currently supported.", version);
        }

        // Each section gives its ID and byte size at the beginning of it, so we can easily read each section.
        while reader.addr < reader.data.len() {
            let id = reader.read_byte().expect("Failed to read section ID");
            let size = reader.read_u32().expect("Failed to read section size");
            let data = reader.read_bytes(size as usize).expect("Failed to read section data");
            sections.push(Section { id, size, data });
        }
        
        sections
    }
}
