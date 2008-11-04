#ifndef MODULEPRIV_HH
#define MODULEPRIV_HH
#define WANT_MOD_USE_COUNT 1	/* glue.hh should use the actual macros */
#include <click/router.hh>
#include <click/driver.hh>
#include <click/error.hh>
#include "moduleparm.h"

#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <asm/uaccess.h>
#include <linux/poll.h>
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 0)
# error "Linux version too old"
#endif

#if 0
# define MDEBUG(args...) do { printk("<1>kclick: " args); printk("\n"); } while (0)
#else
# define MDEBUG(args...) /* nada */
#endif

// see static_assert in clickfs.cc
#define HANDLER_DIRECT			(Handler::DRIVER_FLAG_0)
#define HANDLER_DONE			(Handler::DRIVER_FLAG_0 << 1)
#define HANDLER_RAW			(Handler::DRIVER_FLAG_0 << 2)
#define HANDLER_SPECIAL_INODE		(Handler::DRIVER_FLAG_0 << 3)
#define HANDLER_WRITE_UNLIMITED		(Handler::DRIVER_FLAG_0 << 4)
struct click_handler_direct_info;

class KernelErrorHandler : public BaseErrorHandler { public:

    KernelErrorHandler()
	: _head(0), _tail(0), _wrapped(false) {
    }
    void handle_text(Seriousness, const String &);
    void clear_log() {
	_head = _tail = 0;
	_wrapped = false;
    }
    String read(click_handler_direct_info *hdi) const;

  private:

    enum { logbuf_siz = 4096 };
    char _logbuf[logbuf_siz];
    volatile uint32_t _head;
    volatile uint32_t _tail;
    bool _wrapped;

    void log_line(const char *begin, const char *end);

};

extern KernelErrorHandler *click_logged_errh;
void click_clear_error_log();

void click_init_config();
void click_cleanup_config();

extern Master *click_master;
extern Router *click_router;

void click_init_sched(ErrorHandler *);
int click_cleanup_sched();

struct click_fsmode_t {
    int read;
    int write;
    int exec;
    int dir;
    uid_t uid;
    gid_t gid;
};
extern click_fsmode_t click_fsmode;

extern "C" int click_parm(int which);

struct click_handler_direct_info {
    char *buffer;
    size_t count;
    loff_t *store_f_pos;
    String *string;
    int retval;
};

int init_clickfs();
void cleanup_clickfs();

#endif
