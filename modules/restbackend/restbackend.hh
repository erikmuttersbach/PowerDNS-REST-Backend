#ifndef RESTBACKEND_HH
#define RESTBACKEND_HH

#include <string>
#include <vector>
#include <sys/types.h>
#include <regex.h>
#include <boost/shared_ptr.hpp>

#include "pdns/namespaces.hh"

class QueryCtx;
class ListCtx;
class Regex;

class RestBackend: public DNSBackend {
public:
	RestBackend(const string &suffix);
	~RestBackend();
	bool list(const string &target, int domain_id);
	void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId);
	bool get(DNSResourceRecord &rr);

private:
	cJSON *performRequest(string &fullUri, string &content);
	DNSResourceRecord getRR(cJSON* json);

	string service;
	string uri;
	string host;
	Regex *regex;
	bool log;

	vector<DNSResourceRecord> rrs;

	static boost::asio::io_service io_service;
	boost::asio::ip::tcp::tcp::resolver::iterator endpoint_iterator;
};

class RestFactory: public BackendFactory {
public:
	RestFactory();
	DNSBackend *make(const string &suffix);
	void declareArguments(const string &suffix="");
};

class RestLoader {
public:
	RestLoader();
};

// Holds the information needed to perform a request
// to the rest backend
class QueryCtx {
public:
	QType qtype;
	string qname;
	int zoneId;
	string localIp;
	string remoteIp;
	string realRemoteIp;
};

// RegEx wrapper, copied from the pipe-backend
class Regex {
public:
	Regex(const string &expr) {
		if (regcomp(&d_preg, expr.c_str(), REG_ICASE | REG_NOSUB | REG_EXTENDED))
			throw AhuException("Regular expression did not compile");
	}

	~Regex() {
		regfree(&d_preg);
	}

	// call this to find out if 'line' matches your expression
	bool match(const string &line) {
		return regexec(&d_preg, line.c_str(), 0, 0, 0) == 0;
	}

private:
	regex_t d_preg;
};

#endif

