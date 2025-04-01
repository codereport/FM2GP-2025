
// Semigroup trait
// Only requirement for op is that it is associative

pub trait Integer: Eq + Ord {
    fn half(&self) -> Self;
    fn odd(&self) -> bool;
    fn even(&self) -> bool {
        !self.odd()
    }
    fn zero() -> Self;
    fn one() -> Self;
    fn inc(&self) -> Self;
    fn dec(&self) -> Self;
}


impl Integer for u64 {
    fn zero() -> u64 {
        0
    }

    fn one() -> u64 {
        1
    }
    
    fn half(&self) -> Self {
        self >> 1
    }
    
    fn odd(&self) -> bool {
        self & 1 == 1
    }
    
    fn inc(&self) -> Self {
        *self + 1
    }
    
    fn dec(&self) -> Self {
        *self - 1
    }
    
}


// Multiply semigroup. See https://www.stepanovpapers.com/Journeys/Journeys-0.3.pdf
pub fn power_accumulate<C: Clone, I: Integer, S> (mut r: C, mut a: C, mut n: I, op: S) -> C 
    where S: Fn(&C,&C) -> C
{
    
    if n == Integer::zero() {
        return r;
    }
    loop {
        if n.odd() {
            r = op(&r, &a);
            if n <= Integer::one() {
                return r;
            }
        }

        n = n.half();
        a = op(&a, &a);
    }
}

pub fn power<C: Clone, I: Integer, S> (mut a: C, mut n: I, op: S) -> C
where S: Fn(&C,&C) -> C
 {
    while !n.odd() {
        a = op(&a, &a);
        n = n.half();
    }
    if n == Integer::one() {
        return a;
    }
    power_accumulate(a.clone(), op(&a, &a), n.dec().half(), op)
}
