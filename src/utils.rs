#[macro_export]
macro_rules! ch {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) ^ (!$x & $z)
    };
}

#[macro_export]
macro_rules! parity {
    ($x:expr, $y:expr, $z:expr) => {
        $x ^ $y ^ $z
    };
}

#[macro_export]
macro_rules! maj {
    ($x:expr, $y:expr, $z:expr) => {
        ($x & $y) ^ ($x & $z) ^ ($y & $z)
    };
}

#[macro_export]
macro_rules! sigma0 {
    ($x:expr) => {
        $x.rotate_right(7)  ^ $x.rotate_right(18) ^ ($x >> 3)
    };
}

#[macro_export]
macro_rules! sigma1 {
    ($x:expr) => {
        $x.rotate_right(17)  ^ $x.rotate_right(19) ^ ($x >> 10)
    };
}

#[macro_export]
macro_rules! big_sigma0 {
    ($x:expr) => {
        $x.rotate_right(2) ^ $x.rotate_right(13) ^ $x.rotate_right(22)
    };
}

#[macro_export]
macro_rules! big_sigma1 {
    ($x:expr) => {
        $x.rotate_right(6) ^ $x.rotate_right(11) ^ $x.rotate_right(25)
    };
}