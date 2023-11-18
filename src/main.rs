use std::net::{Ipv4Addr, UdpSocket};

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

    /* ---- Read part ---- */

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
        if pos < self.buf.len() {
            self.pos = pos;
            return Ok(());
        }

        Err("Out of buffer".into())
    }

    /// Read a single byte and step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer (read function)".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte
    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer (get function)".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer (get_range function)".into());
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


    /* ---- Write part ---- */

    /// Write a byte on the buffer at the current position
    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer (write function)".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// Write a byte on the buffer
    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    /// Write two bytes on the buffer
    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    /// Write four bytes on the buffer
    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    /// Write a query name in labeled form
    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let mut len = 0;
        let mut at = 0usize;
        for c in qname.chars() {
            if c == '.' {
                self.write_u8(len as u8)?;
                for i in 0..len {
                    self.write_u8(qname.chars().nth(at + i).unwrap() as u8)?;
                }
                at = at + len + 1;
                len = 0;
            }
            else {
                len += 1;
            }
        }

        self.write_u8(len as u8)?;
        for i in 0..len {
            self.write_u8(qname.chars().nth(at + i).unwrap() as u8)?;
        }


        self.write_u8(0)?;

        Ok(())
    }
    /*
    * Better function ->
    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err("Single label exceeds 63 characters of lenght".into());
            }

            self.write_u8(len as u8)?;
            println!("Scrivi: {len} -> {label}");
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }
        
        self.write_u8(0)?;
        
        Ok(())
    }
    */



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

    /// Write a new Dns Header
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8) |
            ((self.truncate_message as u8) << 1) |
            ((self.authoritative_answer as u8) << 2) |
            ((self.opcode) << 3) |
            ((self.response as u8) << 7) as u8
        )?;

        buffer.write_u8(
            (self.rescode as u8) |
            ((self.checking_disabled as u8) << 4) |
            ((self.authed_data as u8) << 5) |
            ((self.z as u8) << 6) |
            ((self.recursion_available as u8) << 7)
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

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
    // Read the qname from the packet
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    /// Write the qname to the buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?; // write name

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?; // write type number
        buffer.write_u16(1)?; // ?
        
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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A { 
                ref domain, 
                ref addr, 
                ttl 
            } => {
                    buffer.write_qname(domain)?;
                    buffer.write_u16(QueryType::A.to_num())?;
                    buffer.write_u16(1)?;
                    buffer.write_u32(ttl)?;
                    buffer.write_u16(4)?;

                    let octets = addr.octets();
                    buffer.write_u8(octets[0])?;
                    buffer.write_u8(octets[1])?;
                    buffer.write_u8(octets[2])?;
                    buffer.write_u8(octets[3])?;
            },
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
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

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for q in &self.questions {
            q.write(buffer)?;
        }
        for a in &self.answers {
            a.write(buffer)?;
        }
        for a in &self.authorities {
            a.write(buffer)?;
        }
        for r in &self.resources {
            r.write(buffer)?;
        }

        Ok(())
    }
}

/* == Main == */
/// Stub resolver with UDP socket that does most of the work
fn main() -> Result<()> {
    let qname = "repubblica.it";
    let qtype = QueryType::A;

    // Using google public DNS server
    let server = ("8.8.8.8", 53);

    // Bind UDP socket to arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    // Write packet to a buffer
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // Send it to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.

    let packet = DnsPacket::from_buffer(&mut res_buffer)?;
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














