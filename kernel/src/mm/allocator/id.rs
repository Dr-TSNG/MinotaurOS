use alloc::collections::VecDeque;
pub struct IdAllocator {
    cur: usize,
    recycled: VecDeque<usize>,
}

impl IdAllocator {
    pub const fn new() -> Self {
        Self { cur: 0, recycled: VecDeque::new() }
    }

    pub fn alloc(&mut self) -> usize {
        match self.recycled.pop_front() {
            Some(id) => id,
            None => {
                self.cur += 1;
                self.cur - 1
            }
        }
    }

    pub fn dealloc(&mut self, id: usize) {
        self.recycled.push_back(id);
    }
}
