extern crate byteorder;
extern crate hex_slice;

use std::io::Read;
use std::str;

use byteorder::{ReadBytesExt,BigEndian,ByteOrder};
use hex_slice::AsHex;

fn main() {
  let cert_der = include_bytes!("yubico_u2f.der");
  decode_element(cert_der).ok();
}

#[derive(Clone,PartialEq,Debug)]
enum Class {
  Universal,
  Application,
  ContextSpecific,
  Private,
}

#[derive(Clone,PartialEq,Debug)]
enum Style {
  Primitive,
  Constructed,
}

#[derive(Clone,PartialEq,Debug)]
enum UniversalType {
  EndOfContent,
  Boolean,
  Integer,
  BitString,
  OctetString,
  Null,
  ObjectIdentifier,
  ObjectDescriptor,
  External,
  Real,
  Enumerated,
  EmbeddedPdv,
  Utf8String,
  RelativeObjectIdentifier,
  Sequence,
  Set,
  NumericString,
  PrintableString,
  T61String,
  VideotexString,
  IA5String,
  UtcTime,
  GeneralizedTime,
  GraphicString,
  VisibleString,
  GeneralString,
  UniversalString,
  CharacterString,
  BmpString,
  
  Reserved,
  Unknown,
}
impl From<u8> for UniversalType {
  fn from(n: u8) -> Self {
    match n {
      0x00 => UniversalType::EndOfContent,
      0x01 => UniversalType::Boolean,
      0x02 => UniversalType::Integer,
      0x03 => UniversalType::BitString,
      0x04 => UniversalType::OctetString,
      0x05 => UniversalType::Null,
      0x06 => UniversalType::ObjectIdentifier,
      0x07 => UniversalType::ObjectDescriptor,
      0x08 => UniversalType::External,
      0x09 => UniversalType::Real,
      0x0a => UniversalType::Enumerated,
      0x0b => UniversalType::EmbeddedPdv,
      0x0c => UniversalType::Utf8String,
      0x0d => UniversalType::RelativeObjectIdentifier,
      0x0e => UniversalType::Reserved,
      0x0f => UniversalType::Reserved,
      0x10 => UniversalType::Sequence,
      0x11 => UniversalType::Set,
      0x12 => UniversalType::NumericString,
      0x13 => UniversalType::PrintableString,
      0x14 => UniversalType::T61String,
      0x15 => UniversalType::VideotexString,
      0x16 => UniversalType::IA5String,
      0x17 => UniversalType::UtcTime,
      0x18 => UniversalType::GeneralizedTime,
      0x19 => UniversalType::GraphicString,
      0x1a => UniversalType::VisibleString,
      0x1b => UniversalType::GeneralString,
      0x1c => UniversalType::UniversalString,
      0x1d => UniversalType::CharacterString,
      0x1e => UniversalType::BmpString,
      _    => UniversalType::Unknown,
    }
  }
}

fn decode_element(mut s: &[u8]) -> Result<(),std::io::Error> {
  //println!("{:x}", s.as_hex());

  while s.len() > 0 {
    let typ = try!(s.read_u8());

    let class = match typ & 0xc0 {
      0x00 => Class::Universal,
      0x40 => Class::Application,
      0x80 => Class::ContextSpecific,
      0xc0 => Class::Private,

      _ => unimplemented!(),
    };

    let structure = match typ & 0x20 {
      0x00 => Style::Primitive,
      0x20 => Style::Constructed,

      _ => unimplemented!(),
    };

    let tag = {
      match typ & 0x1f {
        0x1f => unimplemented!(),
        n    => UniversalType::from(n),
      }
    };

    let length = match try!(s.read_u8()) as usize {
      0x80          => unimplemented!(),
      n if n < 0x80 => n,
      n             => {
        let nbytes = n & 0x7f;
        let mut len: usize = 0;
        for _ in 0..nbytes {
          len = len << 8;
          len = len | try!(s.read_u8()) as usize;
        }
        len
      }
    };

    println!("class {:?} structure {:?} tag {:?} length {}", class, structure, tag, length);

    let data = {
      let mut buf = vec![0; length].into_boxed_slice();
      try!(s.read_exact(&mut buf[..]));
      buf
    };

    match class {
      Class::Universal => {
        let d = data.as_ref();
        match tag {
          UniversalType::Integer          => try!(decode_integer(d)),
          UniversalType::OctetString      => try!(decode_octet_string(d)),
          UniversalType::BitString        => try!(decode_bit_string(d)),
          UniversalType::ObjectIdentifier => try!(decode_object_identifier(d)),
          UniversalType::Utf8String       => try!(decode_utf8_string(d)),
          UniversalType::PrintableString  => try!(decode_printable_string(d)),
          UniversalType::UtcTime          => try!(decode_utc_time(d)),
          UniversalType::GeneralizedTime  => try!(decode_generalized_time(d)),

          UniversalType::Sequence         => try!(decode_element(d)),
          UniversalType::Set              => try!(decode_element(d)),

          _ => unimplemented!(),
        };
      },
      Class::Application     => unimplemented!(),
      Class::ContextSpecific => {
        match tag {
          UniversalType::EndOfContent => (),
          _ => try!(decode_element(data.as_ref())),
        };
      },
      Class::Private         => unimplemented!(),
    }
  }

  Ok(())
}

fn decode_integer(s: &[u8]) -> Result<(),std::io::Error> {
  let val: i64 = match s.len() {
    n if n == 0 => 0,
    n if n == 2 => BigEndian::read_i16(&s[..]) as i64,
    n if n == 4 => BigEndian::read_i32(&s[..]) as i64,
    n if n == 8 => BigEndian::read_i64(&s[..]),

    _ => unimplemented!(),
  };

  println!("INTEGER {:x}", val);

  Ok(())
}

fn decode_octet_string(s: &[u8]) -> Result<(),std::io::Error> {
  println!("OCTET STRING {:x}", s.as_hex());
  Ok(())
}

fn decode_bit_string(s: &[u8]) -> Result<(),std::io::Error> {
  println!("BIT STRING {:x}", s.as_hex());
  Ok(())
}

fn decode_object_identifier(mut s: &[u8]) -> Result<(),std::io::Error> {
  let oid: Vec<u64> = match s.len() {
    n if n == 0 => vec!(),
    _ => {
      let mut oid = vec!();
      oid.extend_from_slice({
        let first = try!(s.read_u8()) as u64;
        &[first/40, first%40]
      });
      s.iter().fold(0u64, |v, &b| {
        let vv = v * 128 + (b & 0x7f) as u64;
        match b & 0x80 {
          0x80 => vv,
          _ => {
            oid.push(vv);
            0
          },
        }
      });
      oid
    },
  };

  println!("OID {:?}", oid);

  Ok(())
}

fn decode_utf8_string(s: &[u8]) -> Result<(),std::io::Error> {
  let ss = str::from_utf8(s).unwrap(); // XXX validity
  println!("UTF8 STRING {}", ss);
  Ok(())
}

fn decode_printable_string(s: &[u8]) -> Result<(),std::io::Error> {
  let ss = str::from_utf8(s).unwrap(); // XXX validity
  println!("PRINTABLE STRING {}", ss);
  Ok(())
}

fn decode_utc_time(s: &[u8]) -> Result<(),std::io::Error> {
  let ss = str::from_utf8(s).unwrap(); // XXX validity
  // XXX actually produce a date object
  println!("UTC TIME {}", ss);
  Ok(())
}

fn decode_generalized_time(s: &[u8]) -> Result<(),std::io::Error> {
  let ss = str::from_utf8(s).unwrap(); // XXX validity
  // XXX actually produce a date object
  println!("GENERALIZED TIME {}", ss);
  Ok(())
}
