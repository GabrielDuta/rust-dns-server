use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

/* == BytePacketBuffer == */
/// Represents the Dns packet in bytes

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize // position we are reading
}

impl BytePacketBuffer {

    /// Gives us a fresh buffer for the packet contents.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer { 
            buf: [0; 512], 
            pos: 0 
        }
    }

    /// Current position within the buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of times
    fn step(&mut self, steps: usize) -> Result<()> {
        if self.pos + steps < self.buf.len() {
            self.pos += steps;
            return Ok(());
        }

        Err("Buffer overflow".into())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > 0 && pos < self.buf.len() {
            self.pos = pos;
            return Ok(());
        }

        Err("Out of buffer".into())
    }

    /// Read a single byte and step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte
    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16); // bit manipulation to
        // create a valid u16

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a qname
    ///
    /// Reading domain names, taking labels into considerationa
    /// Example input: [3]www[6]google[3]com[0]
    /// Output to outstr: www.google.com
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we can find jumps we keep track of the position locally
        // This allow us to move our shared position to a point past our
        // current qname.
        // This variable keeps track of the position in the current qname
        let mut pos = self.pos();

        // track whether or not we have jumped
        let mut jumped = false;
        let max_jumps = 5; // maximum number of jumps to avoid infinite cycles
        let mut jumps_performed = 0;

        // String delimiter at first empty, then initialized to '.'
        let mut delim = "";
        loop {
            // DNS packets are untrusted data
            // The packet could be crafted with a cycle in the jump instructions
            // to perform unlimited jumps
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // Beginning of label. Lenght in bytes of label
            let len = self.get(pos)?;

            // If two most significant bytes are set -> jump to other offset
            // in the packet
            if (len & 0xC0) == 0xC0 {

                // Update the buffer position to a point past the current label
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and jump by
                // updating our local position
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that jump was performed
                jumped = true;
                jumps_performed += 1;
            }
            
            // Base scenario, we are reading a single label and appendig
            // it to the output
            else {
                pos += 1;

                // Domain names terminate with an empty label
                if len == 0 {
                    break;
                }

                outstr.push_str(delim);
                // Excract actual ASCII bytes
                let str = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str).to_lowercase());

                delim = ".";

                // Move forward the lenght of the label
                pos += len as usize;
            }
        }

        // If we didn't jump update the value of the position in the buffer
        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

/* == ResultCode == */
/// Enum for the values of 'rescode' field:

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

/* == DnsHeader == */
/// Header with information on the packet

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // packet identifier, response packet must have the same id

    pub recursion_desired: bool, // set by the sender if the server should 
    // attempt to resolve the query recursively
    pub truncate_message: bool, // set if message exceeds 512 bytes
    pub authoritative_answer: bool, // set if server that responds is authoritative
    pub opcode: u8, // tipically always 0
    pub response: bool, // 0 for queries, 1 for responses

    pub rescode: ResultCode, // set by server to indicate status of response
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool, // reserved
    pub recursion_available: bool, // set by the server to indicate whether 
    // or not recursion is available

    // number of _ :
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader { 
            id: 0, 

            recursion_desired: false, 
            truncate_message: false, 
            authoritative_answer: false, 
            opcode: 0, 
            response: false, 
            
            rescode: ResultCode::NOERROR, 
            checking_disabled: false, 
            authed_data: false, 
            z: false, 
            recursion_available: false, 
            
            questions: 0, 
            answers: 0, 
            authoritative_entries: 0, 
            resource_entries: 0 
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncate_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;
        
        Ok(())
    }
}


/* == QueryType == */
/// Record type being queried

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A // 1
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num)
        }
    }
}

/* == DnsQuestion == */
/// Query name (domain) and record type

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { 
            name, 
            qtype
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }
}

/* == DnsRecord == */
/// Representation of the DNS record

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        ttl: u32,
        data_len: u16
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    }
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        let res = match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8
                );
                DnsRecord::A{
                    domain,
                    addr,
                    ttl
                }
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    ttl,
                    data_len
                }
            }
        };

        Ok(res)
    }
}

/* == DnsPacket == */
/// Representation of the whole DNS packet

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut res = DnsPacket::new();
        res.header.read(buffer)?;

        for _ in 0..res.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            res.questions.push(question);
        }
        for _ in 0..res.header.answers {
            let rec = DnsRecord::read(buffer)?;
            res.answers.push(rec);
        }
        for _ in 0..res.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            res.authorities.push(rec);
        }
        for _ in 0..res.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            res.resources.push(rec);
        }

        Ok(res)
    }
}

/* == Main == */
fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    println!("\nQuestions:");
    for q in packet.questions {
        println!("{:#?}", q);
    }
    println!("\nAnswers:");
    for a in packet.answers {
        println!("{:#?}", a);
    }
    println!("\nAuthorities:");
    for a in packet.authorities {
        println!("{:#?}", a);
    }
    println!("\nResources:");
    for r in packet.resources {
        println!("{:#?}", r);
    }

    Ok(())
}














