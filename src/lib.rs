use ctor::ctor;
use lazy_static::lazy_static;
use libc::{addrinfo, c_int, c_void, dlsym, AF_UNSPEC, AI_ADDRCONFIG, AI_V4MAPPED, RTLD_NEXT};
use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::mem::transmute;
use std::os::raw::c_char;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// How many milliseconds to cache resolver data.
const CACHE_LIFETIME_MS: u64 = 10000;

// Maximum amount of unfree'd data.
const MAX_GARBAGE_SIZE: usize = 1000;

type GetAddrInfoFn = fn(*const c_char, *const c_char, *const addrinfo, *mut *mut addrinfo) -> i32;
type FreeAddrInfoFn = fn(*mut addrinfo);

//
// Init pointers to original functions
//

static mut orig_getaddrinfo: Option<GetAddrInfoFn> = None;
static mut orig_freeaddrinfo: Option<FreeAddrInfoFn> = None;

#[ctor]
fn init() {
    unsafe {
        let gai = CString::new("getaddrinfo").expect("CString::new failed");
        let ptr = dlsym(RTLD_NEXT, gai.as_ptr());
        orig_getaddrinfo = Some(transmute::<*mut c_void, GetAddrInfoFn>(ptr));

        let fai = CString::new("freeaddrinfo").expect("CString::new failed");
        let ptr = dlsym(RTLD_NEXT, fai.as_ptr());
        orig_freeaddrinfo = Some(transmute::<*mut c_void, FreeAddrInfoFn>(ptr));
    }
}

//
// Cache for responses
//

#[derive(Eq, Hash, PartialEq)]
struct CacheKey {
    hostname: String,
    servname: String,
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
}

impl CacheKey {
    fn new(hostname: *const c_char, servname: *const c_char, hints: *const addrinfo) -> Self {
        if hints.is_null() {
            Self {
                hostname: from_raw(hostname),
                servname: from_raw(servname),
                socktype: 0,
                protocol: 0,
                family: AF_UNSPEC,
                flags: AI_V4MAPPED | AI_ADDRCONFIG,
            }
        } else {
            Self {
                hostname: from_raw(hostname),
                servname: from_raw(servname),
                socktype: unsafe { (*hints).ai_socktype },
                protocol: unsafe { (*hints).ai_protocol },
                family: unsafe { (*hints).ai_family },
                flags: unsafe { (*hints).ai_flags },
            }
        }
    }
}

struct CacheEntry {
    timestamp: u64,
    ai: *mut addrinfo,
    retval: i32,
}

unsafe impl Send for CacheEntry {}

#[derive(Eq, Hash, PartialEq)]
struct AddrInfoWrapper(*mut addrinfo);

unsafe impl Send for AddrInfoWrapper {}

lazy_static! {
    static ref REF_COUNTS: Mutex<HashMap<AddrInfoWrapper, i32>> = Mutex::new(HashMap::new());
    static ref CACHE: Mutex<HashMap<CacheKey, CacheEntry>> = Mutex::new(HashMap::new());
    static ref GARBAGE: Mutex<VecDeque<AddrInfoWrapper>> = Mutex::new(VecDeque::new());
}

fn from_raw(chars: *const c_char) -> String {
    if chars.is_null() {
        return "".to_string();
    } else {
        unsafe { CStr::from_ptr(chars).to_str().unwrap().to_string() }
    }
}

//
// Reference counting helpers
//

fn inc_ref_count(ptr: *mut addrinfo) -> i32 {
    println!("Increasing ref count for pointer {}", ptr as u64);
    let mut ref_counts = REF_COUNTS.lock().unwrap();
    let ref_key = AddrInfoWrapper(ptr);

    let count = ref_counts.get_mut(&ref_key);
    match count {
        Some(count) => {
            *count = *count + 1;
            return *count;
        }
        None => {
            println!("Creating ref count for pointer {}", ptr as usize);
            ref_counts.insert(ref_key, 1);
            return 1;
        }
    }
}

fn dec_ref_count(ptr: *mut addrinfo) -> i32 {
    println!("Decreasing ref count for pointer {}", ptr as u64);
    let mut ref_counts = REF_COUNTS.lock().unwrap();
    let ref_key = AddrInfoWrapper(ptr);

    let count = ref_counts.get_mut(&ref_key);
    match count {
        Some(count) => {
            *count = *count - 1;
            return *count;
        }
        None => {
            println!("Logic error: decreasing refcount on unknown pointer");
            return 0;
        }
    }
}

fn get_ref_count(ptr: *mut addrinfo) -> i32 {
    let mut ref_counts = REF_COUNTS.lock().unwrap();
    let ref_key = AddrInfoWrapper(ptr);

    let count = ref_counts.get_mut(&ref_key);
    match count {
        Some(count) => {
            return *count;
        }
        None => {
            println!("Logic error: decreasing refcount on unknown pointer");
            return -1;
        }
    }
}

//
// Function overrides
//

#[no_mangle]
pub extern "C" fn getaddrinfo(
    hostname: *const c_char,
    servname: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> i32 {
    let mut timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let key = CacheKey::new(hostname, servname, hints);

    let cache = CACHE.lock().unwrap();

    if let Some(value) = cache.get(&key) {
        println!("Found data from cache");
        if timestamp - value.timestamp > CACHE_LIFETIME_MS {
            println!("Data is stale, so performing new lookup");
        } else {
            let count = inc_ref_count(value.ai);
            if count > 0 {
                unsafe {
                    *res = value.ai;
                }
                return value.retval;
            }
        }
    }

    // Release locks before doing expensive DNS lookup
    drop(cache);

    // Cache miss, so do DNS lookup and cache result
    println!("Performing DNS lookup");
    let retval = unsafe { orig_getaddrinfo.unwrap()(hostname, servname, hints, res) };
    if retval < 0 {
        println!("Lookup error, so not caching result");
    }

    timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let data = unsafe {
        CacheEntry {
            timestamp: timestamp,
            ai: *res,
            retval: retval,
        }
    };

    let mut cache = CACHE.lock().unwrap();

    inc_ref_count(data.ai);
    cache.insert(key, data);

    retval
}

#[no_mangle]
pub extern "C" fn freeaddrinfo(ai: *mut addrinfo) {
    // Always grab cache lock, so refcounts do not change while cache lock is held.
    println!("freeaddrinfo() called");
    let _cache = CACHE.lock().unwrap();
    dec_ref_count(ai);

    let mut garbage = GARBAGE.lock().unwrap();

    garbage.push_back(AddrInfoWrapper(ai));

    if garbage.len() > MAX_GARBAGE_SIZE {
        let removed = garbage.pop_front().unwrap();

        // We might have handed out the pointer from the cache.
        if get_ref_count(removed.0) < 1 {
            println!("Freeing pointer: {}", removed.0 as u64);
            unsafe { return orig_freeaddrinfo.unwrap()(removed.0) }
        }
    }
}
