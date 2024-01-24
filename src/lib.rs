// Caches DNS queries made through getaddrinfo()
//
// Data structures
// ===============
// - CACHE: Hash table from getaddrinfo() params to responses.
// - PARAMS: Hash table with pointers to cache keys.
// - REF_COUNTS: Hash table with pointers to reference counts
// - DEFER_QUEUE: Queue for deferred deletions.
//
// Typically an application performs getaddrinfo()/freeaddrinfo() calls as a pair.
// If we instantly remove any data once it has no more references, then we never
// get any cache hits. The solution is to instead add any free'd addrinfo pointers
// to a defer list.
//
// The idea of the defer list is that a pointer with no references will get free'd
// only after DEFER_CALL_COUNT calls to freeaddrinfo() has been made.
//
// All operations lock the cache prior to any changes, so the code has a global
// lock to simplify implementation. DNS queries should be rare enough that this
// should make no difference in practice.

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
const CACHE_LIFETIME_MS: u64 = 1000;

// Maximum amount of unfree'd and unused pointers.
const DEFER_CALL_COUNT: usize = 1000;

type GetAddrInfoFn = fn(*const c_char, *const c_char, *const addrinfo, *mut *mut addrinfo) -> i32;
type FreeAddrInfoFn = fn(*mut addrinfo);

fn from_raw(chars: *const c_char) -> String {
    if chars.is_null() {
        "".to_string()
    } else {
        unsafe { CStr::from_ptr(chars).to_str().unwrap().to_string() }
    }
}

//
// Init pointers to original functions
//

static mut orig_getaddrinfo: Option<GetAddrInfoFn> = None;
static mut orig_freeaddrinfo: Option<FreeAddrInfoFn> = None;

#[ctor]
fn init() {
    println!("Loading libc DNS resolver cacher");
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

#[derive(Eq, Hash, PartialEq, Clone)]
struct GetAddrInfoParams {
    hostname: String,
    servname: String,
    flags: c_int,
    family: c_int,
    socktype: c_int,
    protocol: c_int,
}

impl GetAddrInfoParams {
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

struct Response {
    timestamp: u64,
    ai: *mut addrinfo,
    retval: i32,
}
unsafe impl Send for Response {}

#[derive(Eq, Hash, PartialEq)]
struct AddrInfoWrapper(*mut addrinfo);

unsafe impl Send for AddrInfoWrapper {}

lazy_static! {
    static ref CACHE: Mutex<HashMap<GetAddrInfoParams, Response>> = Mutex::new(HashMap::new());
    static ref PARAMS: Mutex<HashMap<AddrInfoWrapper, GetAddrInfoParams>> =
        Mutex::new(HashMap::new());
}

//
// Deferred deletion logic
//

#[derive(Clone)]
struct RefCount {
    refs: i32,
    deleted: bool,
}

lazy_static! {
    static ref REF_COUNTS: Mutex<HashMap<AddrInfoWrapper, RefCount>> = Mutex::new(HashMap::new());
    static ref DEFER_QUEUE: Mutex<VecDeque<AddrInfoWrapper>> = Mutex::new(VecDeque::new());
}

fn inc_ref_count(ptr: *mut addrinfo) -> RefCount {
    let mut ref_counts = REF_COUNTS.lock().unwrap();
    let ref_key = AddrInfoWrapper(ptr);

    let count = ref_counts.get_mut(&ref_key);
    match count {
        Some(count) => {
            count.refs += 1;
            RefCount {
                refs: count.refs,
                deleted: count.deleted,
            }
        }
        None => {
            ref_counts.insert(
                ref_key,
                RefCount {
                    refs: 1,
                    deleted: false,
                },
            );
            RefCount {
                refs: 1,
                deleted: false,
            }
        }
    }
}

fn defer_delete_ptr(ptr: *mut addrinfo) {
    let mut ref_counts = REF_COUNTS.lock().unwrap();
    let ref_key = AddrInfoWrapper(ptr);

    let count = ref_counts.get_mut(&ref_key);
    match count {
        Some(count) => {
            count.refs -= 1;
            if !count.deleted {
                let mut queue = DEFER_QUEUE.lock().unwrap();
                queue.push_back(AddrInfoWrapper(ptr));
                count.deleted = true;
            }
        }
        None => {
            println!("Logic error: deleting an unknown pointer");
        }
    }
}

fn get_ref_count(ptr: *mut addrinfo) -> RefCount {
    let mut ref_counts = REF_COUNTS.lock().unwrap();
    let ref_key = AddrInfoWrapper(ptr);

    let count = ref_counts.get_mut(&ref_key);
    match count {
        Some(count) => count.clone(),
        None => {
            println!("Logic error: asking refcount on unknown pointer");
            RefCount {
                refs: -1,
                deleted: false,
            }
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

    let params = GetAddrInfoParams::new(hostname, servname, hints);
    let mut cache = CACHE.lock().unwrap();

    let cached = cache.get(&params);
    if let Some(value) = cached {
        if timestamp - value.timestamp < CACHE_LIFETIME_MS {
            inc_ref_count(value.ai);
            unsafe {
                *res = value.ai;
            }
            return value.retval;
        }

        PARAMS.lock().unwrap().remove(&AddrInfoWrapper(value.ai));
        cache.remove(&params);
    }

    // Release locks before doing expensive DNS lookup
    drop(cache);

    let retval = unsafe { orig_getaddrinfo.unwrap()(hostname, servname, hints, res) };

    // Do not cache responses that are failures.
    if retval < 0 {
        return retval;
    }

    timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let response = Response {
        timestamp,
        ai: unsafe { *res },
        retval,
    };
    let ai = response.ai;

    let mut cache = CACHE.lock().unwrap();

    // If someone else filled cache before us, remove the value.
    if let Some(value) = cache.get(&params) {
        PARAMS.lock().unwrap().remove(&AddrInfoWrapper(value.ai));
    }

    inc_ref_count(response.ai);
    cache.insert(params.clone(), response);
    PARAMS.lock().unwrap().insert(AddrInfoWrapper(ai), params);

    retval
}

#[no_mangle]
pub extern "C" fn freeaddrinfo(ai: *mut addrinfo) {
    // Always grab cache lock, so refcounts do not change while cache lock is held.
    let mut cache = CACHE.lock().unwrap();

    defer_delete_ptr(ai);

    let mut queue = DEFER_QUEUE.lock().unwrap();

    if queue.len() > DEFER_CALL_COUNT {
        let deferred = queue.pop_front().unwrap();

        let refs = get_ref_count(deferred.0);
        if refs.refs > 0 {
            return;
        }

        // Cleanup any cached data about the pointer.
        REF_COUNTS.lock().unwrap().remove(&deferred);
        let mut params = PARAMS.lock().unwrap();
        if let Some(p) = params.remove(&deferred) {
            cache.remove(&p);
        }

        unsafe { orig_freeaddrinfo.unwrap()(deferred.0) }
    }
}
