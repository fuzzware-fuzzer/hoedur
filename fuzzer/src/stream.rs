use std::ops::Range;

use common::{hashbrown::hash_map::Entry, FxHashMap};
use modeling::input::InputContext;

#[derive(Debug, Clone)]
pub struct ChronoStream {
    chrono_stream: Vec<StreamIndex>,
    reverse_lookup: FxHashMap<InputContext, Vec<usize>>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct StreamIndex {
    pub context: InputContext,
    pub index: usize,
}

impl ChronoStream {
    pub fn from_access_log(access_log: Vec<InputContext>) -> Self {
        // keep track of stream index (forward lookup)
        let mut index: FxHashMap<_, usize> = FxHashMap::default();
        let mut next_index = |context| {
            *(match index.entry(context) {
                Entry::Occupied(entry) => {
                    let index = entry.into_mut();
                    *index += 1;
                    index
                }
                Entry::Vacant(entry) => entry.insert(0),
            })
        };

        let mut chrono_stream = Vec::with_capacity(access_log.len());
        let mut reverse_lookup: FxHashMap<_, Vec<_>> = FxHashMap::default();

        for context in access_log {
            // add input stream to chrono stream lookup entry (reverse lookup)
            reverse_lookup
                .entry(context.clone())
                .or_default()
                .push(chrono_stream.len());

            // create chrono stream entry
            let index = next_index(context.clone());
            chrono_stream.push(StreamIndex { context, index });
        }

        Self {
            chrono_stream,
            reverse_lookup,
        }
    }

    pub fn len(&self) -> usize {
        self.chrono_stream.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chrono_stream.is_empty()
    }

    pub fn contains(&self, context: &InputContext) -> bool {
        self.reverse_lookup.contains_key(context)
    }

    pub fn chrono_index(&self, target: &StreamIndex) -> Option<usize> {
        self.reverse_lookup
            .get(&target.context)
            .and_then(|lookup| lookup.get(target.index).or_else(|| lookup.last()).copied())
    }

    pub fn stream_range(
        &self,
        context: &InputContext,
        chrono_range: &Range<usize>,
    ) -> Option<Range<usize>> {
        self.reverse_lookup.get(context).map(|entry| {
            let start = entry
                .binary_search(&chrono_range.start)
                .unwrap_or_else(|index| index);

            let end = if chrono_range.is_empty() {
                // reuse start for empty range
                start
            } else {
                // binary search from start
                start
                    + entry[start..]
                        .binary_search(&chrono_range.end)
                        .unwrap_or_else(|index| index)
            };

            start..end
        })
    }

    pub fn skip_until(&self, target: &StreamIndex) -> impl Iterator<Item = &StreamIndex> {
        let index = self.chrono_index(target);

        self.chrono_stream
            .iter()
            .skip(index.unwrap_or(self.chrono_stream.len()))
    }

    pub fn next_target(&self, target: &StreamIndex) -> Option<StreamIndex> {
        self.skip_until(target).nth(1).cloned()
    }
}

impl AsRef<[StreamIndex]> for ChronoStream {
    fn as_ref(&self) -> &[StreamIndex] {
        &self.chrono_stream
    }
}
