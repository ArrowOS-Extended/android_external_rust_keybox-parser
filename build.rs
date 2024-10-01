use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use base64::decode;
use xml::reader::{EventReader, XmlEvent};

fn clean_pem_data(pem: &str) -> String {
    pem.lines()
        .filter(|line| {
            !line.starts_with("-----BEGIN") && !line.starts_with("-----END")
        })
        .collect::<Vec<&str>>()
        .join("")
}

fn read_ec_data_from_xml(file_path: &str) -> Result<(Vec<String>, Option<String>), Box<dyn std::error::Error>> {
    let file = File::open(file_path);

    if let Err(_) = file {
        // If file is not found, return empty vectors
        return Ok((Vec::new(), None));
    }

    let parser = EventReader::new(file.unwrap());

    let mut inside_certificate = false;
    let mut inside_private_key = false;
    let mut is_ecdsa = false;
    let mut certs: Vec<String> = Vec::new();
    let mut private_key: Option<String> = None;

    for event in parser {
        match event? {
            XmlEvent::StartElement { name, attributes, .. } => {
                if name.local_name == "Key" {
                    for attr in attributes {
                        if attr.name.local_name == "algorithm" && attr.value == "ecdsa" {
                            is_ecdsa = true;
                        }
                    }
                }
                if name.local_name == "Certificate" && is_ecdsa {
                    inside_certificate = true;
                }
                if name.local_name == "PrivateKey" && is_ecdsa {
                    inside_private_key = true;
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == "Key" {
                    is_ecdsa = false;
                }
                if name.local_name == "Certificate" {
                    inside_certificate = false;
                }
                if name.local_name == "PrivateKey" {
                    inside_private_key = false;
                }
            }
            XmlEvent::Characters(text) => {
                if inside_certificate && is_ecdsa {
                    certs.push(clean_pem_data(&text));
                }
                if inside_private_key && is_ecdsa {
                    private_key = Some(clean_pem_data(&text));
                }
            }
            _ => {}
        }
    }

    Ok((certs, private_key))
}

fn write_rust_constants(file_path: &Path, certs: Vec<String>, private_key: Option<String>) -> std::io::Result<()> {
    let mut output_file = BufWriter::new(OpenOptions::new().write(true).create(true).open(file_path)?);

    writeln!(output_file, "// Auto-generated constants\n")?;

    // Function to write bytes in groups of 10 per line
    fn write_bytes(output_file: &mut BufWriter<File>, bytes: &[u8]) -> std::io::Result<()> {
        for (i, byte) in bytes.iter().enumerate() {
            if i % 10 == 0 {
                if i != 0 {
                    writeln!(output_file)?;
                }
                write!(output_file, "    ")?; 
            }
            write!(output_file, "0x{:02x}, ", byte)?; // Write each byte
        }
        writeln!(output_file) 
    }

    // Always write three certificate constants, defaulting to empty arrays if needed
    for i in 1..=3 {
        if let Some(cert) = certs.get(i - 1) {
            if let Ok(decoded_cert) = decode(cert.trim()) {
                writeln!(output_file, "pub const EC_CERTIFICATE_{}: &[u8] = &[", i)?;
                write_bytes(&mut output_file, &decoded_cert)?; // Write the bytes with 10 per line
                writeln!(output_file, "];\n")?;
            } else {
                writeln!(output_file, "pub const EC_CERTIFICATE_{}: &[u8] = &[];\n", i)?;
            }
        } else {
            writeln!(output_file, "pub const EC_CERTIFICATE_{}: &[u8] = &[];\n", i)?;
        }
    }

    // Write the private key if it exists, otherwise an empty array
    if let Some(key) = private_key {
        if let Ok(decoded_key) = decode(key.trim()) {
            writeln!(output_file, "pub const EC_PRIVATE_KEY: &[u8] = &[")?;
            write_bytes(&mut output_file, &decoded_key)?; // Write the bytes with 10 per line
            writeln!(output_file, "];\n")?;
        }
    } else {
        writeln!(output_file, "pub const EC_PRIVATE_KEY: &[u8] = &[];\n")?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let generated_file_path = Path::new("src/ec_constants.rs");

    let path = std::env::var("KEYBOX_PATH")?;
    
    let file_path = Path::new(&path).join("keybox.xml");

    let file_path_str = file_path.to_str().ok_or("Invalid UTF-8 in path")?;

    let (certs, private_key) = read_ec_data_from_xml(file_path_str)?;

    write_rust_constants(&generated_file_path, certs, private_key)?;

    Ok(())
}
