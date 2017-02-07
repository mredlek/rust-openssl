use ffi;
use libc::{c_long, c_char};
use std::fmt;
use std::ptr;
use std::slice;
use std::str;

use {cvt, cvt_p};
use bio::MemBio;
use error::ErrorStack;
use types::{OpenSslType, OpenSslTypeRef};
use string::OpensslString;
use nid::Nid;

type_!(Asn1GeneralizedTime, Asn1GeneralizedTimeRef, ffi::ASN1_GENERALIZEDTIME, ffi::ASN1_GENERALIZEDTIME_free);

impl fmt::Display for Asn1GeneralizedTimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = try!(MemBio::new());
            try!(cvt(ffi::ASN1_GENERALIZEDTIME_print(mem_bio.as_ptr(), self.as_ptr())));
            write!(f, "{}", str::from_utf8_unchecked(mem_bio.get_buf()))
        }
    }
}

type_!(Asn1Time, Asn1TimeRef, ffi::ASN1_TIME, ffi::ASN1_TIME_free);

impl fmt::Display for Asn1TimeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = try!(MemBio::new());
            try!(cvt(ffi::ASN1_TIME_print(mem_bio.as_ptr(), self.as_ptr())));
            write!(f, "{}", str::from_utf8_unchecked(mem_bio.get_buf()))
        }
    }
}

impl Asn1Time {
    fn from_period(period: c_long) -> Result<Asn1Time, ErrorStack> {
        ffi::init();

        unsafe {
            let handle = try!(cvt_p(ffi::X509_gmtime_adj(ptr::null_mut(), period)));
            Ok(Asn1Time::from_ptr(handle))
        }
    }

    /// Creates a new time on specified interval in days from now
    pub fn days_from_now(days: u32) -> Result<Asn1Time, ErrorStack> {
        Asn1Time::from_period(days as c_long * 60 * 60 * 24)
    }
}

type_!(Asn1String, Asn1StringRef, ffi::ASN1_STRING, ffi::ASN1_STRING_free);

impl Asn1StringRef {
    pub fn as_utf8(&self) -> Result<OpensslString, ErrorStack> {
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = ffi::ASN1_STRING_to_UTF8(&mut ptr, self.as_ptr());
            if len < 0 {
                return Err(ErrorStack::get());
            }

            Ok(OpensslString::from_ptr(ptr as *mut c_char))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(ASN1_STRING_data(self.as_ptr()), self.len()) }
    }

    pub fn len(&self) -> usize {
        unsafe { ffi::ASN1_STRING_length(self.as_ptr()) as usize }
    }
}

type_!(Asn1Integer, Asn1IntegerRef, ffi::ASN1_INTEGER, ffi::ASN1_INTEGER_free);

impl Asn1IntegerRef {
    pub fn get(&self) -> i64 {
        unsafe {
            ::ffi::ASN1_INTEGER_get(self.as_ptr()) as i64
        }
    }

    pub fn set(&mut self, value: i32) -> Result<(), ErrorStack>
    {
        unsafe {
            cvt(::ffi::ASN1_INTEGER_set(self.as_ptr(), value as c_long)).map(|_| ())
        }
    }
}

type_!(Asn1Type, AsnTypeRef, ffi::ASN1_TYPE, ffi::ASN1_TYPE_free);

type_!(Asn1Object, Asn1ObjectRef, ffi::ASN1_OBJECT, ffi::ASN1_OBJECT_free);

impl Asn1Object {
    fn new() -> Asn1Object
    {
        unsafe {
            Asn1Object::from_ptr(::ffi::ASN1_OBJECT_new())
        }
    }

    fn from_nid(nid: Nid) -> Result<Self,ErrorStack>
    {
        unsafe {
            let handle = try!(cvt_p(::ffi::OBJ_nid2obj(nid.as_raw())));
            Ok(Asn1Object::from_ptr(handle))
        }
    }
}

impl Asn1ObjectRef {

    fn nid(&self) -> Option<Nid>
    {
        let nid = unsafe {
            ::ffi::OBJ_obj2nid(self.as_ptr())
        };
        if nid == ::ffi::NID_undef {
            None
        } else {
            Some(Nid::from_raw(nid))
        }
    }

    pub fn text(&self) -> &str
    {
        unsafe {
            let mut buf = Vec::<u8>::with_capacity(80);
            let size = ::ffi::OBJ_obj2txt(buf.as_mut_ptr() as *mut i8, 80, self.as_ptr(), 0);
            let cstr = ::std::ffi::CStr::from_ptr(buf.as_ptr() as *const i8);
            cstr.to_str().unwrap()
        }
    }
}

impl Clone for Asn1Object {
    fn clone(&self) -> Self
    {
        unsafe {
            Asn1Object::from_ptr(::ffi::OBJ_dup(self.as_ptr()))
        }
    }
}

impl ::std::fmt::Display for Asn1ObjectRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result
    {
        fmt.write_str(self.text())
    }
}

type_!(Asn1OctetString, Asn1OctetStringRef, ffi::ASN1_OCTET_STRING, ffi::ASN1_OCTET_STRING_free);

impl Asn1OctetStringRef
{

}

impl Clone for Asn1OctetString {
    fn clone(&self) -> Self
    {
        unsafe {
            Asn1OctetString::from_ptr(::ffi::ASN1_OCTET_STRING_dup(self.as_ptr()))
        }
    }
}

impl ::std::fmt::Display for Asn1OctetStringRef
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            let mem_bio = try!(MemBio::new());
            try!(cvt(ffi::ASN1_STRING_print(mem_bio.as_ptr(), self.as_ptr() as *const ffi::ASN1_STRING)));
            write!(f, "{}", str::from_utf8_unchecked(mem_bio.get_buf()))
        }
    }
}

impl super::stack::Stackable for Asn1Object
{
    type StackType = ffi::stack_st_ASN1_OBJECT;
}

type_!(Asn1BitString, Asn1BitStringRef, ffi::ASN1_BIT_STRING, ffi::ASN1_BIT_STRING_free);

impl Asn1BitStringRef {
    pub fn get_bit(self, n: i32) -> bool
    {
        unsafe {
            ffi::ASN1_BIT_STRING_get_bit(self.as_ptr(), n) != 0
        }
    }

    pub fn set_bit(self, n: i32, value: bool) -> Result<(), ErrorStack>
    {
        unsafe {
            cvt(ffi::ASN1_BIT_STRING_set_bit(self.as_ptr(), n, if value { 1 } else {0})).map(|_| ())
        }
    }
}

#[cfg(any(ossl101, ossl102))]
use ffi::ASN1_STRING_data;

#[cfg(ossl110)]
#[allow(bad_style)]
unsafe fn ASN1_STRING_data(s: *mut ffi::ASN1_STRING) -> *mut ::libc::c_uchar {
    ffi::ASN1_STRING_get0_data(s) as *mut _
}
