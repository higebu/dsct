//! Reusable UTF-8-aware cursor buffer for text input fields.

/// A string buffer with a byte-offset cursor, handling UTF-8 boundaries correctly.
///
/// Used by [`super::state::FilterState`] and [`super::state::CommandState`] to
/// avoid duplicating delicate cursor movement logic.
#[derive(Default, Clone, Debug)]
pub struct CursorBuffer {
    /// The text content.
    pub input: String,
    /// Cursor position as a byte offset into `input`.
    pub cursor: usize,
}

impl CursorBuffer {
    /// Create a new empty `CursorBuffer`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a character at the current cursor position and advance the cursor.
    pub fn insert_char(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Delete the character before the cursor (like pressing Backspace).
    ///
    /// Returns `true` if a character was deleted, `false` if the cursor was
    /// already at position 0.
    pub fn backspace(&mut self) -> bool {
        if self.cursor > 0 {
            let prev = self.input[..self.cursor]
                .chars()
                .next_back()
                .map_or(0, |c| c.len_utf8());
            self.cursor -= prev;
            self.input.remove(self.cursor);
            true
        } else {
            false
        }
    }

    /// Move the cursor one character to the left.
    pub fn move_left(&mut self) {
        if self.cursor > 0 {
            let prev = self.input[..self.cursor]
                .chars()
                .next_back()
                .map_or(0, |c| c.len_utf8());
            self.cursor -= prev;
        }
    }

    /// Move the cursor one character to the right.
    pub fn move_right(&mut self) {
        if self.cursor < self.input.len() {
            let next = self.input[self.cursor..]
                .chars()
                .next()
                .map_or(0, |c| c.len_utf8());
            self.cursor += next;
        }
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_ascii() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('h');
        buf.insert_char('i');
        assert_eq!(buf.input, "hi");
        assert_eq!(buf.cursor, 2);
    }

    #[test]
    fn insert_multibyte() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('日');
        buf.insert_char('本');
        assert_eq!(buf.input, "日本");
        assert_eq!(buf.cursor, 6); // 3 bytes per CJK char
    }

    #[test]
    fn backspace_ascii() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('a');
        buf.insert_char('b');
        assert!(buf.backspace());
        assert_eq!(buf.input, "a");
        assert_eq!(buf.cursor, 1);
    }

    #[test]
    fn backspace_multibyte() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('é'); // 2-byte UTF-8
        assert!(buf.backspace());
        assert_eq!(buf.input, "");
        assert_eq!(buf.cursor, 0);
    }

    #[test]
    fn backspace_at_start() {
        let mut buf = CursorBuffer::new();
        assert!(!buf.backspace());
    }

    #[test]
    fn move_left_ascii() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.move_left();
        assert_eq!(buf.cursor, 1);
        buf.move_left();
        assert_eq!(buf.cursor, 0);
        buf.move_left(); // no-op at start
        assert_eq!(buf.cursor, 0);
    }

    #[test]
    fn move_right_ascii() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.cursor = 0;
        buf.move_right();
        assert_eq!(buf.cursor, 1);
        buf.move_right();
        assert_eq!(buf.cursor, 2);
        buf.move_right(); // no-op at end
        assert_eq!(buf.cursor, 2);
    }

    #[test]
    fn move_left_right_multibyte() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('あ'); // 3 bytes
        buf.insert_char('い'); // 3 bytes
        assert_eq!(buf.cursor, 6);
        buf.move_left();
        assert_eq!(buf.cursor, 3);
        buf.move_right();
        assert_eq!(buf.cursor, 6);
    }

    #[test]
    fn insert_at_middle() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('a');
        buf.insert_char('c');
        buf.move_left();
        buf.insert_char('b');
        assert_eq!(buf.input, "abc");
        assert_eq!(buf.cursor, 2);
    }

    #[test]
    fn backspace_at_middle() {
        let mut buf = CursorBuffer::new();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.insert_char('c');
        buf.move_left();
        buf.backspace();
        assert_eq!(buf.input, "ac");
        assert_eq!(buf.cursor, 1);
    }

    #[test]
    fn is_empty() {
        let mut buf = CursorBuffer::new();
        assert!(buf.is_empty());
        buf.insert_char('x');
        assert!(!buf.is_empty());
        buf.backspace();
        assert!(buf.is_empty());
    }
}
