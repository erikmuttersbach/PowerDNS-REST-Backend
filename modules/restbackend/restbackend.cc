#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <pdns/dns.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "cJSON.h"

#include "restbackend.hh"

#define LOGID	"[rest-backend] "

boost::asio::io_service RestBackend::io_service;

RestBackend::RestBackend(const string &suffix) {
	try {
		setArgPrefix("rest");
		this->service = getArg("service");
		this->regex = getArg("regex").empty() ? 0 : new Regex(getArg("regex"));
		this->log = false;
	}
	catch(const ArgException &A) {
		L<<Logger::Error<<LOGID"Fatal argument error: "<<A.reason<<endl;
		throw;
	}

	try {
		this->log = ::arg().mustDo("query-logging") || mustDo("logging-query");
	} catch(const ArgException &A) {

	}

	if(this->service.empty()) {
		L<<Logger::Error<<LOGID"Fatal argument error: argument rest-service is empty"<<endl;
		throw new ArgException;
	}

	// Parse the host to be used in the http request,
	// REST endpoints should check for the presence and correctness of
	// the Host header for security reasons.
	bool https = (this->service.substr(0, 5).compare("https") == 0);
	this->host = this->service.substr(https ? 8 : 7, this->service.length());
	int sp = this->host.find_first_of("/", 1);
	this->uri = this->host.substr(sp, this->host.length());
	this->host = this->host.substr(0, sp);

	// Setup boost::asio networking
	using boost::asio::ip::tcp;
	tcp::resolver resolver(io_service);
	tcp::resolver::query query(this->host, "http");
	this->endpoint_iterator = resolver.resolve(query);
}

RestBackend::~RestBackend() {
	if(this->regex) {
		delete this->regex;
	}
}

bool RestBackend::list(const string &target, int domain_id) {
	std::stringstream content;
	content << "target=" << target << "&";
	content << "domainId=" << domain_id << "\r\n";

	if(this->log) {
		L<<Logger::Info << "Requesting list for "+target << endl;
	}

	string fullUri = string(this->uri+"/list");
	string contentStr = content.str();
	cJSON *json = this->performRequest(fullUri, contentStr);
	if(!json) {
		return false;
	}

	for(int i=0; i<cJSON_GetArraySize(json); i++) {
		cJSON *jsonRR = cJSON_GetArrayItem(json, i);
		DNSResourceRecord rr = this->getRR(jsonRR);
		this->rrs.push_back(rr);
	}

	cJSON_Delete(json);

	return true;
}

void RestBackend::lookup(const QType &qtype, const string &qname, DNSPacket *p, int zoneId) {
 	 if(this->regex && this->regex->match(qname+";"+qtype.getName())) {
 		if(this->log) {
 			L<<Logger::Warning<< qname+";"+qtype.getName() << " does not match regex " << endl;
 		}
 		return;
	 }

	// Prepare request parameters
	std::stringstream content;
	content << "qtype=" << qtype.getName() << "&";
	content << "qname=" << qname << "&";
	content << "zoneId=" << zoneId << "&";
	content << "remoteIp=" << p->getRemote() << "&";
	content << "localIp=" << p->getLocal() << "&";
	content << "realRemoteIp=" << p->getRealRemote().toString() << "\r\n";

	try {
		if(this->log) {
			L<<Logger::Info << "Requesting "+qtype.getName() << " for domain " << qname << endl;
		}

		string fullUri = string(this->uri+"/lookup");
		string contentStr = content.str();
		cJSON *json = this->performRequest(fullUri, contentStr);
		if(!json) {
			return;
		}

		DNSResourceRecord rr = this->getRR(json);
		this->rrs.push_back(rr);

		cJSON_Delete(json);

	} catch (std::exception& e) {
		L<<Logger::Error<<LOGID"An error occurred creating the resource record: " << e.what() << endl;
		throw new AhuException(e.what());
	}
}

DNSResourceRecord RestBackend::getRR(cJSON* json) {
	DNSResourceRecord rr;

	rr.scopeMask = 0; // TODO
	rr.auth = 1;	  // TODO

	cJSON *qname = cJSON_GetObjectItem(json, "qname");
	if(qname) {
		rr.qname = qname->valuestring;
	}

	cJSON *qtype = cJSON_GetObjectItem(json, "qtype");
	if(qtype) {
		rr.qtype = qtype->valuestring;
	}

	cJSON *ttl = cJSON_GetObjectItem(json, "ttl");
	if(ttl) {
		rr.ttl = ttl->valueint;
	}

	cJSON *domainId = cJSON_GetObjectItem(json, "id");
	if(domainId) {
		rr.domain_id = domainId->valueint;
	}

	cJSON *priority = cJSON_GetObjectItem(json, "priority");
	if(priority) {
		rr.priority = priority->valueint;
	}

	cJSON *content = cJSON_GetObjectItem(json, "content");
	if(content) {
		rr.content = string(content->valuestring);
	}

	return rr;
}

bool RestBackend::get(DNSResourceRecord &rr) {
	if(this->rrs.size() > 0) {
		rr = this->rrs[0];
		this->rrs.erase(this->rrs.begin());
		return true;
	}

	return false;
}

// Performs a request to the rest service.
// In case of an error, an AhuException is thrown, if 404 is returned
// this function returns false.
cJSON *RestBackend::performRequest(string &fullUri, string &content) {
	using boost::asio::ip::tcp;

	try {
		// Create socket and request
		tcp::socket socket(this->io_service);
		boost::asio::connect(socket, this->endpoint_iterator);

		boost::asio::streambuf requestBuf;
		std::ostream request(&requestBuf);
		request << "POST " << fullUri << " HTTP/1.1\r\n";
		request << "Host: " << this->host << "\r\n";
		request << "Accept: */*\r\n";
		request << "Content-Length: " << content.length() << "\r\n";
		request << "Content-Type: application/x-www-form-urlencoded\r\n";
		request << "Connection: close\r\n\r\n";
		request << content;

		// Send the request.
		boost::asio::write(socket, requestBuf);

		// Read the response status line. The response streambuf will automatically
		// grow to accommodate the entire line. The growth may be limited by passing
		// a maximum size to the streambuf constructor.
		boost::asio::streambuf response;
		boost::asio::read_until(socket, response, "\r\n");

		// Check that response is OK.
		std::istream response_stream(&response);
		std::string http_version;
		response_stream >> http_version;
		unsigned int status_code;
		response_stream >> status_code;
		std::string status_message;
		std::getline(response_stream, status_message);
		if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
			L<<Logger::Error << LOGID"HTTP response from backend was invalid"<< endl;
			throw new AhuException;
		}
		else if(status_code == 404) {
			return NULL;
		}
		if (status_code != 200) {
			L<<Logger::Error << LOGID"HTTP response code " << status_code << " not recognized"<< endl;
			throw new AhuException;
		}

		// Read the response headers, which are terminated by a blank line.
		boost::asio::read_until(socket, response, "\r\n\r\n");

		// Process the response headers.
		std::string header;
		while (std::getline(response_stream, header) && header != "\r") {
			// Discard headers
		}

		// Read whatever content we already have
		std::stringstream responseContent;
		if (response.size() > 0) {
			responseContent << &response;
		}

		// Read until EOF, writing data to output as we go.
		boost::system::error_code error;
		while (boost::asio::read(socket, response, boost::asio::transfer_at_least(1), error))
			responseContent << &response;
		if (error != boost::asio::error::eof)
			throw boost::system::system_error(error);

		cJSON *json = cJSON_Parse(responseContent.str().c_str());
		if(json) {
			return json;
		}
		else {
			throw new AhuException("Could not parse JSON "+responseContent.str());
		}

	} catch (std::exception& e) {

		throw new AhuException(e.what());
	}
}

// RestFactory
RestFactory::RestFactory() : BackendFactory("rest") {
}

DNSBackend *RestFactory::make(const string &suffix) {
	return new RestBackend(suffix);
}

void RestFactory::declareArguments(const string &suffix) {
	declare(suffix, "service", "HTTP url to the REST service", "");
	declare(suffix, "regex","Only queries that match this regular expression will be resolved by this backend","");
}

// RestLoader
RestLoader::RestLoader() {
	BackendMakers().report(new RestFactory);
}

static RestLoader restLoader;
