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

#[no_mangle]
pub extern "C" fn valider_http_status_retryable(status: u16) -> bool {
    matches!(status, 408 | 425 | 429 | 500 | 502 | 503 | 504)
}

#[no_mangle]
pub unsafe extern "C" fn valider_parse_retry_after(
    value: *const u8,
    length: usize,
    seconds_out: *mut u64,
) -> bool {
    if value.is_null() || seconds_out.is_null() || length == 0 || length > 20 {
        return false;
    }

    let bytes = unsafe { core::slice::from_raw_parts(value, length) };
    let mut seconds = 0_u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return false;
        }
        let Some(next) = seconds
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(*byte - b'0')))
        else {
            return false;
        };
        seconds = next;
    }

    unsafe {
        *seconds_out = seconds;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{
        valider_http_status_class, valider_http_status_retryable,
        valider_parse_retry_after, HttpStatusClass,
    };

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

    #[test]
    fn identifies_common_retryable_statuses_without_retrying() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert!(valider_http_status_retryable(status));
        }
        assert!(!valider_http_status_retryable(200));
        assert!(!valider_http_status_retryable(404));
    }

    #[test]
    fn parses_only_bounded_numeric_retry_after_values() {
        let mut seconds = 0;
        let value = b"120";
        assert!(unsafe {
            valider_parse_retry_after(value.as_ptr(), value.len(), &mut seconds)
        });
        assert_eq!(seconds, 120);

        for invalid in [&b""[..], &b"Wed, 21 Oct 2015 07:28:00 GMT"[..], &b"18446744073709551616"[..]] {
            assert!(!unsafe {
                valider_parse_retry_after(invalid.as_ptr(), invalid.len(), &mut seconds)
            });
        }
    }
}
