#![cfg_attr(not(test), no_std)]

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpStatusClass {
    Invalid = 0,
    Informational = 1,
    Success = 2,
    Redirection = 3,
    ClientError = 4,
    ServerError = 5,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn valider_http_status_class(status: u16) -> i32 {
    match status / 100 {
        1 => HttpStatusClass::Informational as i32,
        2 => HttpStatusClass::Success as i32,
        3 => HttpStatusClass::Redirection as i32,
        4 => HttpStatusClass::ClientError as i32,
        5 => HttpStatusClass::ServerError as i32,
        _ => HttpStatusClass::Invalid as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::{valider_http_status_class, HttpStatusClass};

    #[test]
    fn classifies_http_status_ranges() {
        assert_eq!(valider_http_status_class(100), HttpStatusClass::Informational as i32);
        assert_eq!(valider_http_status_class(200), HttpStatusClass::Success as i32);
        assert_eq!(valider_http_status_class(302), HttpStatusClass::Redirection as i32);
        assert_eq!(valider_http_status_class(404), HttpStatusClass::ClientError as i32);
        assert_eq!(valider_http_status_class(503), HttpStatusClass::ServerError as i32);
        assert_eq!(valider_http_status_class(99), HttpStatusClass::Invalid as i32);
        assert_eq!(valider_http_status_class(600), HttpStatusClass::Invalid as i32);
    }
}
