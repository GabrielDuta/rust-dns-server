
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
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of times
    pub fn step(&mut self, steps: usize) -> Result<()> {
        if self.pos + steps < self.buf.len() {
            self.pos += steps;
            return Ok(());
        }

        Err("Buffer overflow".into())
    }

    /// Change the buffer position
    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos < self.buf.len() {
            self.pos = pos;
            return Ok(());
        }

        Err("Out of buffer".into())
    }

    /// Read a single byte and step forward
    pub fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer (read function)".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte
    pub fn get(&self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer (get function)".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer (get_range function)".into());
        }
        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16); // bit manipulation to
        // create a valid u16

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> Result<u32> {
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
    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
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
    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer (write function)".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// Write a byte on the buffer
    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    /// Write two bytes on the buffer
    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    /// Write four bytes on the buffer
    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    /// Write a query name in labeled form
    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
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

    pub fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }

    pub(crate) fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}
