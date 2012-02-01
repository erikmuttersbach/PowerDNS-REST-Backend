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
	}
	catch(const ArgException &A) {
		L<<Logger::Error<<LOGID"Fatal argument error: "<<A.reason<<endl;
		throw;
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

bool RestBackend::list(const string &target, int domain_id) {
	return false;
}

void RestBackend::lookup(const QType &qtype, const string &qname, DNSPacket *p, int zoneId) {
 	 if(!(this->regex && !this->regex->match(qname+";"+qtype.getName()))) {
		 this->ctx = new QueryCtx();
		 this->ctx->qtype = QType(qtype);
		 this->ctx->qname = qname;
		 this->ctx->zoneId = zoneId;
		 this->ctx->localIp = p->getLocal();
		 this->ctx->realRemoteIp = p->getRealRemote().toString();
		 this->ctx->remoteIp = p->getRemote();
	 }
	 else {
		 cout << qname+";"+qtype.getName() << " does not match regex " << endl;

		 if(this->ctx) {
			 this->ctx = 0;
		 }
	 }
}

bool RestBackend::get(DNSResourceRecord &rr) {
	using boost::asio::ip::tcp;

	if(!this->ctx) {
		cout << "RETURNING WITHOUT RESPONSE" << endl;
		return false;
	}

	// Prepare request parameters
	std::stringstream content;
	content << "qtype=" << this->ctx->qtype.getName() << "&";
	content << "qname=" << this->ctx->qname << "&";
	content << "zoneId=" << this->ctx->zoneId << "&";
	content << "remoteIp=" << this->ctx->remoteIp << "&";
	content << "localIp=" << this->ctx->localIp << "&";
	content << "realRemoteIp=" << this->ctx->realRemoteIp << "\r\n";
	string contentStr = content.str();

	cout << "sending request " << contentStr << endl;

	try {
		// Create socket and request
		tcp::socket socket(this->io_service);
		boost::asio::connect(socket, this->endpoint_iterator);

		boost::asio::streambuf requestBuf;
		std::ostream request(&requestBuf);
		request << "POST " << this->uri << "/lookup HTTP/1.1\r\n";
		request << "Host: " << this->host << "\r\n";
		request << "Accept: */*\r\n";
		request << "Content-Length: " << contentStr.length() << "\r\n";
		request << "Content-Type: application/x-www-form-urlencoded\r\n";
		request << "Connection: close\r\n\r\n";
		request << contentStr;

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
			return false;
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

		}

		// Write whatever content we already have to output.
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

		string responseContentStr = responseContent.str();
		cJSON* json = cJSON_Parse(responseContent.str().c_str());
		if(!json) {
			L<<Logger::Error << "Could not parse JSON response " << responseContentStr << endl;
			throw AhuException("Could not parse JSON response");
		}
		else {
			cout << "parsed response " << responseContentStr << endl;
		}

		// Fill DNSResourceRecord
		rr.scopeMask = 0; // TODO
		rr.auth = 1;	  // TODO

		cJSON *qname = cJSON_GetObjectItem(json, "qname");
		if(qname) {
			rr.qname = qname->valuestring;
			if(this->ctx->qname.compare(rr.qname) != 0) {
				L << Logger::Warning << LOGID"backend returned qname '" << rr.qname << "' which is different from request qname '" << this->ctx->qname << "'" << endl;
			}
		}
		else {
			rr.qname = this->ctx->qname;
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
			rr.content = content->valuestring;
		}

	} catch (std::exception& e) {
		L<<Logger::Error<<LOGID"An error occurred creating the resource record: " << e.what() << endl;
		throw new AhuException(e.what());
	}

	delete this->ctx;
	this->ctx = 0;

	return true;
}

// RestFactory
RestFactory::RestFactory() : BackendFactory("rest") {
}

DNSBackend *RestFactory::make(const string &suffix) {
	return new RestBackend(suffix);
}

void RestFactory::declareArguments(const string &suffix) {
	declare(suffix, "service", "HTTP url to the REST service", "http://127.0.0.1/pdns");
	declare(suffix, "regex","Only queries that match this regular expression will be resolved by this backend",".*xfdattacker.com;.*");
}

// RestLoader
RestLoader::RestLoader() {
	BackendMakers().report(new RestFactory);

	L
			<< Logger::Info
			<< " [RestBackend] This is the restbackend ("__DATE__", "__TIME__") reporting"
			<< endl;
}

static RestLoader restLoader;
