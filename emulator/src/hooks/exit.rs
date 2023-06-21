use serde::{Deserialize, Serialize};

use super::HookTarget;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitHook {
    name: Option<String>,
    #[serde(flatten)]
    target: HookTarget,
}
impl ExitHook {
    pub fn new(name: Option<String>, target: HookTarget) -> Self {
        Self { name, target }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref().or_else(|| self.target().name())
    }

    pub fn target(&self) -> &HookTarget {
        &self.target
    }
}
