use serde::{Deserialize, Serialize};

use crate::USize;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
    init_nsvtor: Option<USize>,
    init_svtor: Option<USize>,
    num_irq: Option<u32>,
    systick: Option<bool>,
}

impl Board {
    pub fn set_init_nsvtor(&mut self, init_nsvtor: USize) {
        self.init_nsvtor = Some(init_nsvtor);
    }

    pub fn init_nsvtor(&self) -> Option<USize> {
        self.init_nsvtor
    }

    pub fn set_init_svtor(&mut self, init_svtor: USize) {
        self.init_svtor = Some(init_svtor);
    }

    pub fn init_svtor(&self) -> Option<USize> {
        self.init_svtor
    }

    pub fn set_num_irq(&mut self, num_irq: u32) {
        self.num_irq = Some(num_irq);
    }

    pub fn num_irq(&self) -> u32 {
        self.num_irq.unwrap_or(256)
    }

    pub fn set_systick(&mut self, systick: bool) {
        self.systick = Some(systick);
    }

    pub fn systick(&self) -> bool {
        self.systick.unwrap_or(true)
    }
}
