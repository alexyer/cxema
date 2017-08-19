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