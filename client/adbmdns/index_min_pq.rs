use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::Hash;

// We use an indexed priority queue to maintain the list of RR that need attention. A simple PQ
// would only allow access to the highest priority element but since we receive RR that can be
// located anywhere in the queue, using an IndexPQ allows us to blindly update the RR when we
// receive it.
pub(crate) struct IndexMinPQ<T> {
    data: Vec<T>,
    index: HashMap<T, usize>,
}

impl<T> IndexMinPQ<T> {
    pub(crate) fn clear(&mut self) {
        self.data.clear();
        self.index.clear();
    }
}

pub trait CompareAttention {
    fn cmp_attention(&self, other: &Self) -> Ordering;
}

impl<T> IndexMinPQ<T>
where
    T: Hash + Eq + Clone + CompareAttention,
{
    pub(crate) fn new() -> IndexMinPQ<T> {
        IndexMinPQ { data: Vec::new(), index: HashMap::new() }
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    #[cfg(test)]
    fn empty(&self) -> bool {
        self.data.is_empty()
    }

    fn cmp(item1: &T, item2: &T) -> Ordering {
        item1.cmp_attention(item2)
    }

    pub fn push(&mut self, item: T) {
        if self.index.contains_key(&item) {
            // Item already in the list, this is an update
            let index = self.index[&item];
            let order = IndexMinPQ::cmp(&item, &self.data[index]);
            self.data[index] = item.clone();
            match order {
                Ordering::Equal => {
                    // Nothing to do!
                }
                Ordering::Less => {
                    self.swim(index);
                }
                Ordering::Greater => {
                    self.sink(index);
                }
            }
        } else {
            // Not in the list, insert it
            self.data.push(item.clone());
            self.index.insert(item.clone(), self.last_idx());
            self.swim(self.last_idx());
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.data.is_empty() {
            return None;
        }
        let last_idx = self.last_idx();
        self.swap(0, last_idx);

        let item = self.data.pop();
        // We know that there is at least one item so it is safe to expect
        self.index.remove(&item.clone().expect("data is not empty, yet failed to pop?"));

        if !self.data.is_empty() {
            self.sink(0);
        }

        item
    }

    pub fn peek(&self) -> Option<&T> {
        self.data.first()
    }

    fn parent_idx(&self, i: usize) -> Option<usize> {
        if i == 0 {
            None
        } else {
            Some((i - 1) / 2)
        }
    }

    fn left_child_idx(&self, i: usize) -> usize {
        2 * i + 1
    }

    fn right_child_idx(&self, i: usize) -> usize {
        2 * i + 2
    }

    fn last_idx(&self) -> usize {
        self.data.len() - 1
    }

    fn swap(&mut self, i: usize, j: usize) {
        // Swap the index
        let item_i = &self.data[i];
        let item_j = &self.data[j];
        self.index.insert(item_i.clone(), j);
        self.index.insert(item_j.clone(), i);

        // Swap the heap
        self.data.swap(i, j);
    }

    fn swim(&mut self, mut idx: usize) {
        while let Some(parent_idx) = self.parent_idx(idx) {
            if IndexMinPQ::cmp(&self.data[idx], &self.data[parent_idx]) != Ordering::Less {
                break;
            }
            self.swap(idx, parent_idx);
            idx = parent_idx;
        }
    }

    fn sink(&mut self, mut idx: usize) {
        let last_idx = self.last_idx();
        loop {
            let left_child_idx = self.left_child_idx(idx);
            let right_child_idx = self.right_child_idx(idx);
            let mut smallest_idx = idx;

            if left_child_idx <= last_idx
                && IndexMinPQ::cmp(&self.data[left_child_idx], &self.data[idx]) == Ordering::Less
            {
                smallest_idx = left_child_idx;
            }
            if right_child_idx <= last_idx
                && IndexMinPQ::cmp(&self.data[right_child_idx], &self.data[idx]) == Ordering::Less
                && IndexMinPQ::cmp(&self.data[right_child_idx], &self.data[smallest_idx])
                    == Ordering::Less
            {
                smallest_idx = right_child_idx;
            }

            if smallest_idx != idx {
                self.swap(idx, smallest_idx);
                idx = smallest_idx;
            } else {
                break;
            }
        }
    }

    #[cfg(test)]
    fn into_sorted_vec(mut self) -> Vec<T> {
        let mut ret = vec![];
        while !self.data.is_empty() {
            if let Some(elem) = self.pop() {
                ret.push(elem);
            }
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use crate::index_min_pq::{CompareAttention, IndexMinPQ};
    use std::cmp::Ordering;
    use std::hash::{Hash, Hasher};
    use std::rc::Rc;

    impl CompareAttention for i32 {
        fn cmp_attention(&self, other: &Self) -> Ordering {
            self.cmp(other)
        }
    }

    #[test]
    fn test_empty() {
        let pq: IndexMinPQ<i32> = IndexMinPQ::new();
        assert!(pq.empty());
    }

    #[test]
    fn test_swim() {
        let mut pq = IndexMinPQ::new();
        pq.push(1);
        assert_eq!(pq.len(), 1);
        assert_eq!(pq.pop(), Some(1));
        assert!(pq.empty());
    }

    #[test]
    fn test_sink() {
        let mut pq = IndexMinPQ::new();
        pq.push(1);
        pq.push(2);
        pq.pop();
        assert_eq!(pq.len(), 1);
    }

    #[test]
    fn test_size() {
        let mut pq = IndexMinPQ::new();
        assert_eq!(pq.len(), 0);
        pq.push(1);
        pq.push(2);
        pq.push(3);
        assert_eq!(pq.len(), 3);

        let e = pq.pop();
        assert_eq!(pq.len(), 2);
        assert_eq!(e, Some(1));

        let e = pq.pop();
        assert_eq!(e, Some(2));
        assert_eq!(pq.len(), 1);

        let e = pq.pop();
        assert_eq!(e, Some(3));
        assert_eq!(pq.len(), 0);

        let e = pq.pop();
        assert_eq!(e, None);
    }

    #[test]
    fn test_data_and_index() {
        let mut pq = IndexMinPQ::new();
        pq.push(1);
        pq.push(2);
        assert_eq!(pq.index.len(), 2);
        assert_eq!(pq.data.len(), 2);

        pq.pop();
        assert_eq!(pq.index.len(), 1);
        assert_eq!(pq.data.len(), 1);

        // Try to insert a previously present entry. If index was not properly cleared, this
        // will fail.
        pq.push(1);
        assert_eq!(pq.index.len(), 2);
        assert_eq!(pq.data.len(), 2);
    }

    #[test]
    fn test_peek() {
        let mut pq = IndexMinPQ::new();
        pq.push(1);
        pq.push(2);
        pq.push(3);

        assert_eq!(pq.len(), 3);
        assert_eq!(pq.peek(), Some(&1));

        let mut pq = IndexMinPQ::new();
        pq.push(3);
        pq.push(2);
        pq.push(1);

        assert_eq!(pq.len(), 3);
        assert_eq!(pq.peek(), Some(&1));
    }

    #[test]
    fn test_into_sorted_vec() {
        let mut pq = IndexMinPQ::new();
        pq.push(1);
        pq.push(2);
        pq.push(3);
        assert_eq!(pq.into_sorted_vec(), vec![1, 2, 3]);
    }

    #[test]
    fn test_into_sorted_vec_reversed_insertion_order() {
        let mut pq = IndexMinPQ::new();
        pq.push(3);
        pq.push(2);
        pq.push(1);
        assert_eq!(pq.into_sorted_vec(), vec![1, 2, 3]);
    }

    #[derive(Clone, Debug)]
    struct TestItem {
        value: String,
        deadline: i32,
    }

    impl TestItem {
        fn new(value: String, deadline: i32) -> Self {
            TestItem { value, deadline }
        }
    }

    impl PartialEq<Self> for TestItem {
        fn eq(&self, other: &Self) -> bool {
            self.value.eq(&other.value)
        }
    }

    impl CompareAttention for TestItem {
        fn cmp_attention(&self, other: &Self) -> Ordering {
            self.deadline.cmp(&other.deadline)
        }
    }

    impl Hash for TestItem {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.value.hash(state);
        }
    }

    impl Eq for TestItem {}

    #[test]
    fn test_update() {
        let mut pq = IndexMinPQ::new();

        let item_update = TestItem::new("foo".to_string(), 13);
        pq.push(item_update.clone());
        pq.push(TestItem::new("bar".to_string(), 11));
        pq.push(TestItem::new("see".to_string(), 12));
        assert_eq!(pq.len(), 3);
        assert_eq!(pq.peek(), Some(&TestItem::new("bar".to_string(), 11)));

        let item_update = TestItem::new("foo".to_string(), 2);
        pq.push(item_update.clone());
        assert_eq!(pq.len(), 3);
        assert_eq!(pq.peek(), Some(&item_update));

        let item_update = TestItem::new("see".to_string(), 1);
        pq.push(item_update.clone());
        assert_eq!(pq.peek(), Some(&item_update));

        let new_item = TestItem::new("xxx".to_string(), 1);
        pq.push(new_item);
        assert_eq!(pq.len(), 4);
    }

    #[test]
    fn test_multiple_insert() {
        let mut pq = IndexMinPQ::new();
        pq.push(TestItem::new("v1".to_string(), 1));
        pq.push(TestItem::new("v2".to_string(), 2));
        pq.push(TestItem::new("v3".to_string(), 3));
        pq.push(TestItem::new("v4".to_string(), 4));
        pq.push(TestItem::new("v5".to_string(), 5));
        pq.push(TestItem::new("v6".to_string(), 6));
        pq.push(TestItem::new("v7".to_string(), 7));
        pq.push(TestItem::new("v8".to_string(), 8));

        assert_eq!(
            vec![
                TestItem::new("v1".to_string(), 1),
                TestItem::new("v2".to_string(), 2),
                TestItem::new("v3".to_string(), 3),
                TestItem::new("v4".to_string(), 4),
                TestItem::new("v5".to_string(), 5),
                TestItem::new("v6".to_string(), 6),
                TestItem::new("v7".to_string(), 7),
                TestItem::new("v8".to_string(), 8),
            ],
            pq.into_sorted_vec()
        );
    }

    #[test]
    fn test_multiple_insert_mixed_order() {
        let mut pq = IndexMinPQ::new();
        pq.push(TestItem::new("v3".to_string(), 3));
        pq.push(TestItem::new("v4".to_string(), 4));
        pq.push(TestItem::new("v7".to_string(), 7));
        pq.push(TestItem::new("v8".to_string(), 8));
        pq.push(TestItem::new("v2".to_string(), 2));
        pq.push(TestItem::new("v5".to_string(), 5));
        pq.push(TestItem::new("v1".to_string(), 1));
        pq.push(TestItem::new("v6".to_string(), 6));

        assert_eq!(
            vec![
                TestItem::new("v1".to_string(), 1),
                TestItem::new("v2".to_string(), 2),
                TestItem::new("v3".to_string(), 3),
                TestItem::new("v4".to_string(), 4),
                TestItem::new("v5".to_string(), 5),
                TestItem::new("v6".to_string(), 6),
                TestItem::new("v7".to_string(), 7),
                TestItem::new("v8".to_string(), 8),
            ],
            pq.into_sorted_vec()
        );
    }

    impl CompareAttention for Rc<i32> {
        fn cmp_attention(&self, other: &Self) -> Ordering {
            self.cmp(other)
        }
    }

    #[test]
    fn test_rc_entries_simple() {
        let mut pq = IndexMinPQ::new();

        let one = Rc::new(1);
        let two = Rc::new(2);
        let three = Rc::new(3);
        let four = Rc::new(4);

        pq.push(three.clone());
        pq.push(two.clone());
        pq.push(four.clone());
        pq.push(one.clone());

        assert_eq!(vec![one, two, three, four], pq.into_sorted_vec())
    }

    impl CompareAttention for Rc<TestItem> {
        fn cmp_attention(&self, other: &Self) -> Ordering {
            self.deadline.cmp(&other.deadline)
        }
    }

    #[test]
    fn test_rc_entries() {
        let mut pq = IndexMinPQ::new();

        let one = Rc::new(TestItem::new("thre".to_string(), 1));
        let two = Rc::new(TestItem::new("fab".to_string(), 2));
        let three = Rc::new(TestItem::new("bar".to_string(), 3));
        let four = Rc::new(TestItem::new("foo".to_string(), 4));

        pq.push(four.clone());
        pq.push(one.clone());
        pq.push(three.clone());
        pq.push(two.clone());

        assert_eq!(vec![one, two, three, four], pq.into_sorted_vec())
    }
}
