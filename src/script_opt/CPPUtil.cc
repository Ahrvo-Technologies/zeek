// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/file.h>

#include "zeek/script_opt/CPPUtil.h"

namespace zeek::detail {

std::string Fmt(double d)
	{
	// Special hack to preserve the signed-ness of the magic -0.0.
	if ( d == -0.0 )
		return "-0.0";

	// Unfortunately, to_string(double) is hardwired to use %f with
	// default of 6 digits precision.
	char buf[8192];
	snprintf(buf, sizeof buf, "%.17g", d);
	return buf;
	}

std::string scope_prefix(const std::string& scope)
	{
	return std::string("zeek::detail::CPP_") + scope + "::";
	}

std::string scope_prefix(int scope)
	{
	return scope_prefix(std::to_string(scope));
	}

bool is_CPP_compilable(const ProfileFunc* pf)
	{
	if ( pf->NumWhenStmts() > 0 )
		return false;

	if ( pf->TypeSwitches().size() > 0 )
		return false;

	return true;
	}

void lock_file(const std::string& fname, FILE* f)
	{
	if ( flock(fileno(f), LOCK_EX) < 0 )
		{
		char buf[256];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("flock failed on %s: %s", fname.c_str(), buf);
		exit(1);
		}
	}

void unlock_file(const std::string& fname, FILE* f)
	{
	if ( flock(fileno(f), LOCK_UN) < 0 )
		{
		char buf[256];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("un-flock failed on %s: %s", fname.c_str(), buf);
		exit(1);
		}
	}

} // zeek::detail
