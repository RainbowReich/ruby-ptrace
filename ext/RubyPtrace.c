#include "ruby.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

VALUE RubyPtrace = Qnil;
VALUE Process = Qnil;
pid_t procPid = NULL;

void Init_ruby_ptrace();

//Process methods
void Process_attach(VALUE self, VALUE pid);
void Process_detach(VALUE self);
void Process_set_data(VALUE self, VALUE addr, VALUE data);
void Process_stop(VALUE self);
void Process_continue(VALUE self);
VALUE Process_pid(VALUE self);
VALUE Process_get_data(VALUE self, VALUE addr);



void Init_ruby_ptrace()
{
  RubyPtrace = rb_define_module("RubyPtrace");
  Process = rb_define_class_under(RubyPtrace, "Process", rb_cObject);
  rb_define_method(Process, "attach", Process_attach, 1);
  rb_define_method(Process, "detach", Process_detach, 0);
  rb_define_method(Process, "pid", Process_pid, 0);
  rb_define_method(Process, "set_data", Process_set_data, 2);
  rb_define_method(Process, "get_data", Process_get_data, 1);
  rb_define_method(Process, "stop", Process_stop, 0);
  rb_define_method(Process, "continue", Process_continue, 0);
}

void Process_attach(VALUE self, VALUE pid)
{
  if(ptrace(PTRACE_SEIZE, NUM2INT(pid), NULL, NULL) == -1) {
    if(errno) {
      rb_raise(rb_eSystemCallError, "Error %i: Couldn't attach to process %i", errno, (pid_t)NUM2INT(pid));
    }
  }
  procPid = NUM2INT(pid);
}

void Process_detach(VALUE self)
{
  ptrace(PTRACE_DETACH, procPid, 0, 0);
}

void Process_set_data(VALUE self, VALUE addr, VALUE data)
{
  if(ptrace(PTRACE_POKEDATA, procPid, NUM2INT(addr), NUM2INT(data)) == -1) {
    if(errno) {
      rb_raise(rb_eSystemCallError, "Error %i: Couldn't set data on process %i", errno, procPid);
    }
  }
}

VALUE Process_get_data(VALUE self, VALUE addr)
{
  long retVal = INT2FIX(ptrace(PTRACE_PEEKDATA, procPid, NUM2INT(addr), 0));
  if(retVal == -1)
    if(errno)
      rb_raise(rb_eSystemCallError, "Error %i: Couldn't retrieve data on process %i", errno, procPid);
  return retVal;
}

void Process_stop(VALUE self)
{
  ptrace(PTRACE_INTERRUPT, procPid, 0, 0);
  waitpid(procPid, NULL, 0);
}

void Process_continue(VALUE self)
{
  ptrace(PTRACE_CONT, procPid, 0, 0);
}

VALUE Process_pid(VALUE self)
{
  return NUM2FIX(procPid);
}
