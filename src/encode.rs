#![allow(clippy::cast_ptr_alignment)]

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::error::Error;

static TABLE: &[u8] = b"0123456789abcdef";

pub fn hex_string(src: &[u8]) -> Result<String, Error> {
    let mut buffer = vec![0; src.len() * 2];
    hex_encode(src, &mut buffer).map(|_| unsafe { String::from_utf8_unchecked(buffer) })
}

pub fn hex_encode(src: &[u8], dst: &mut [u8]) -> Result<(), Error> {
    let len = src.len().checked_mul(2).unwrap();
    if dst.len() < len {
        return Err(Error::InvalidLength(len));
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") {
            unsafe { hex_encode_avx2(src, dst) };
            return Ok(());
        }
        if is_x86_feature_detected!("sse4.1") {
            unsafe { hex_encode_sse41(src, dst) };
            return Ok(());
        }
    }

    hex_encode_fallback(src, dst);
    Ok(())
}

macro_rules! mdbg {
    ($val:expr) => {
        match $val {
            tmp => {
                //let mut b = [0u8; 32];
                //_mm256_storeu_si256(b.as_mut_ptr() as *mut _, tmp);
                //eprintln!("[{}:{}] {} = {:02x?}",
                //    std::file!(), std::line!(), std::stringify!($val), b);
                tmp
            }
        }
    };
}

macro_rules! sdbg {
    ($val:expr) => {
        match $val {
            tmp => {
                //let mut b = [0u8; 16];
                //_mm_storeu_si128(b.as_mut_ptr() as *mut _, tmp);
                //eprintln!("[{}:{}] {} = {:02x?}",
                //    std::file!(), std::line!(), std::stringify!($val), b);
                tmp
            }
        }
    };
}

#[deprecated(since = "0.3.0", note = "please use `hex_encode` instead")]
pub fn hex_to(src: &[u8], dst: &mut [u8]) -> Result<(), Error> {
    hex_encode(src, dst)
}

#[target_feature(enable = "avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_encode_avx2(mut src: &[u8], mut dst: &mut [u8]) {
    while src.len() >= 32 {
        let tmp = _mm256_loadu_si256(src.as_ptr() as *const _);
        _mm256_storeu_si256(dst.as_mut_ptr() as *mut _, encode_chunk_avx2(_mm256_castsi256_si128(tmp)));
        _mm256_storeu_si256(dst.as_mut_ptr().offset(32) as *mut _, encode_chunk_avx2(_mm256_extracti128_si256(tmp, 1)));
        src = &src[32..];
        dst = &mut dst[64..];
    }

    hex_encode_sse41(src, dst);
}

#[target_feature(enable="avx2")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn encode_chunk_avx2(input: __m128i) -> __m256i {
    sdbg!(input);
    let out1 = _mm_shuffle_epi8(input, _mm_setr_epi8(
        0, 1, 2, 3, 4, 5, 6, 7,
        0, 1, 2, 3, 4, 5, 6, 7,
    ));
    sdbg!(out1);
    let out2 = _mm_shuffle_epi8(input, _mm_setr_epi8(
        8, 9, 10, 11, 12, 13, 14, 15,
        8, 9, 10, 11, 12, 13, 14, 15,
    ));
    sdbg!(out2);
    let out3 = _mm256_set_m128i(out2, out1);
    mdbg!(out3);
    let out4 = _mm256_srlv_epi64(out3, _mm256_setr_epi64x(4, 0, 4, 0));
    mdbg!(out4);
    let out5 = _mm256_and_si256(out4, _mm256_set1_epi8(0xf));
    mdbg!(out5);
    let out6 = _mm256_shuffle_epi8(out5, _mm256_setr_epi8(
        0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15,
        0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15,
    ));
    mdbg!(out6);
    let offset_lut = _mm256_setr_epi8(
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        87, 87, 87, 87, 87, 87,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        87, 87, 87, 87, 87, 87,
    );
    mdbg!(offset_lut);
    let offsets = _mm256_shuffle_epi8(offset_lut, out6);
    mdbg!(offsets);
    let out9 = _mm256_add_epi8(out6, offsets);
    mdbg!(out9)
}

// copied from https://github.com/Matherunner/bin2hex-sse/blob/master/base16_sse4.cpp
#[target_feature(enable = "sse4.1")]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe fn hex_encode_sse41(mut src: &[u8], dst: &mut [u8]) {
    let ascii_zero = _mm_set1_epi8(b'0' as i8);
    let nines = _mm_set1_epi8(9);
    let ascii_a = _mm_set1_epi8((b'a' - 9 - 1) as i8);
    let and4bits = _mm_set1_epi8(0xf);

    let mut i = 0_isize;
    while src.len() >= 16 {
        let invec = _mm_loadu_si128(src.as_ptr() as *const _);

        let masked1 = _mm_and_si128(invec, and4bits);
        let masked2 = _mm_and_si128(_mm_srli_epi64(invec, 4), and4bits);

        // return 0xff corresponding to the elements > 9, or 0x00 otherwise
        let cmpmask1 = _mm_cmpgt_epi8(masked1, nines);
        let cmpmask2 = _mm_cmpgt_epi8(masked2, nines);

        // add '0' or the offset depending on the masks
        let masked1 = _mm_add_epi8(masked1, _mm_blendv_epi8(ascii_zero, ascii_a, cmpmask1));
        let masked2 = _mm_add_epi8(masked2, _mm_blendv_epi8(ascii_zero, ascii_a, cmpmask2));

        // interleave masked1 and masked2 bytes
        let res1 = _mm_unpacklo_epi8(masked2, masked1);
        let res2 = _mm_unpackhi_epi8(masked2, masked1);

        _mm_storeu_si128(dst.as_mut_ptr().offset(i * 2) as *mut _, res1);
        _mm_storeu_si128(dst.as_mut_ptr().offset(i * 2 + 16) as *mut _, res2);
        src = &src[16..];
        i += 16;
    }

    let i = i as usize;
    hex_encode_fallback(src, &mut dst[i * 2..]);
}

#[inline]
fn hex(byte: u8) -> u8 {
    TABLE[byte as usize]
}

pub fn hex_encode_fallback(src: &[u8], dst: &mut [u8]) {
    for (byte, slots) in src.iter().zip(dst.chunks_mut(2)) {
        slots[0] = hex((*byte >> 4) & 0xf);
        slots[1] = hex(*byte & 0xf);
    }
}

#[cfg(test)]
mod tests {
    use crate::encode::hex_encode_fallback;
    use proptest::{proptest, proptest_helper};
    use std::str;

    fn _test_encode_fallback(s: &String) {
        let mut buffer = vec![0; s.as_bytes().len() * 2];
        hex_encode_fallback(s.as_bytes(), &mut buffer);
        let encode = unsafe { str::from_utf8_unchecked(&buffer[..s.as_bytes().len() * 2]) };
        assert_eq!(encode, hex::encode(s));
    }

    proptest! {
        #[test]
        fn test_encode_fallback(ref s in ".*") {
            _test_encode_fallback(s);
        }
    }
}
