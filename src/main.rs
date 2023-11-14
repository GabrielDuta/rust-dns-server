fn main() {
    let mut b = BytePacketBuffer::new();
    let res = b.read_u16().unwrap();
    print!("{:?}", res);
}

/* == BytePacketBuffer == */

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize
}

impl BytePacketBuffer {

    /// Function that gives us a fresh buffer for
    /// the packet contents.
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
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }
}


























