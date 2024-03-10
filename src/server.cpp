// Server connections and debugging
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
// Strings for comfort
#include <string>
#include <sstream>
#include <cstring>


// === DIRECTORY/FILE HANDLING === //
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;

std::string directory;
fs::path filename_to_full_path(const std::string& filename) {
  return fs::path(directory) / filename;
}

std::string filedata_to_string(std::ifstream& istream) {
  std::stringstream file_contents;
  file_contents << istream.rdbuf();
  return file_contents.str();
}

// === DIRECTORY/FILE HANDLING === //



// === THREAD HANDLING === //
#include <thread>   
#include <csignal>
#include <atomic>
#include <mutex>
#include <vector>

// Credit to user https://app.codecrafters.io/users/codyschierbeck
std::vector<std::thread> threads;
std::mutex threads_mutex;
std::atomic<bool> running(true);

// Not sure what this does, gonna have to look into it deeper
void add_thread(std::thread&& thrd) {
  std::lock_guard<std::mutex> guard(threads_mutex);
  // Have to std::move threads, since they are not CopyAssignable
  threads.push_back(std::move(thrd));
}

// Join threads to main thread
void join_threads() {
  for (auto& thread : threads) {
    if (thread.joinable())
      thread.join();
  }
}

void signalHandler(const int signal) {
  running = false;
}

// === THREAD HANDLING === //
// === RESPONSE/REQUEST HANDLING === //

constexpr std::string http_nl = "\r\n";
const std::string HTTP_200_OK = "200 OK";
const std::string HTTP_404_NF = "404 Not Found";
const std::string HTTP_500_IE = "500 Internal Error";
const std::string CT_TEXT_PLAIN       = "text/plain";
const std::string CT_APP_OCTET_STREAM = "application/octet-stream";

constexpr int buffer_size = 1024;
constexpr int SOCKET_PORT = 4221;

class Response {
private:
  std::string http_ver, code;
  std::string body, headers, content;
  unsigned long content_length;

  void set_content(const std::string& str) noexcept {
    content = str;
    content_length = str.length();
  }
  
  void set_headers(const std::string& header_type) noexcept {
    headers = "Content-Type: " + header_type + http_nl;
    headers += "Content-Length: " + std::to_string(content_length) + http_nl;
  }

public:

  Response() :  http_ver{"HTTP/1.1"}, code{HTTP_404_NF}, body{""}, headers{""}, content{""}, content_length{0} { }
  
  // Highly urged to use only this function, as
  // using set_content() or set_headers() indepoendantly, may lead to bugs
  void set_content_and_headers(const std::string& cont, const std::string& header_type) noexcept {
    set_content(cont);
    set_headers(header_type);
  }

  void set_version(const std::string& version) noexcept { http_ver = version; }
  void set_code(const std::string& c)          noexcept { code = c; }

  void create_body() noexcept {
    body =  http_ver + " " + code + http_nl;
    body += headers + http_nl;
    body += content;
  }

  std::string get_body() const noexcept { return body; }

};

class Request {
private:
  std::string method, path, http_ver;
  std::string host, user_agent;
  Response response;
public:
  Request(const std::string& req) { parseSelf(req); }

  void parseSelf(const std::string& request) {
    std::istringstream iss(request);
    std::string filler;
    iss >> method >> path >> http_ver;
    iss >> filler >> host;
    iss >> filler >> user_agent;

    response.set_version(http_ver);
  }

  void parseSelf(const char* request_cstr, const int& request_size) {
    parseSelf(std::string(request_cstr, request_size));
  }

  void parse_path() {

    if (path == "/") {
      response.set_code(HTTP_200_OK);
      return;
    }

    if (path.starts_with("/echo/")) {
      // /echo/_ <--- [6th index]
      response.set_content_and_headers(path.substr(6), CT_TEXT_PLAIN);
      response.set_code(HTTP_200_OK);
      return;
    }

    if (path.starts_with("/files/")) {
      // /files/_ <--- [7th index]
      auto full_path_to_file = filename_to_full_path(path.substr(7));

      if (!fs::exists(full_path_to_file)) {
        response.set_code(HTTP_404_NF);
        return;
      }

      std::ifstream file(full_path_to_file);
      if (!file.is_open()) {
        response.set_code(HTTP_500_IE);
        return;
      }

      response.set_code(HTTP_200_OK);
      response.set_content_and_headers(filedata_to_string(file), CT_APP_OCTET_STREAM);
      file.close();
      return;
    }

    // 1 is after the first slash: /_ <-
    else if(path.substr(1) == "user-agent") {
      response.set_content_and_headers(user_agent, CT_TEXT_PLAIN);
      return;
    }

    response.set_code(HTTP_404_NF);
  }

  Response get_response() { return response; }
};


// Receives Request, parses it and sends out Response
void handleConnection(int client_fd) {

  char rbuffer[buffer_size];
  ssize_t bytes = recv(client_fd, rbuffer, buffer_size, 0);

  // ERROR CODE 5: Failure to receive data from client connection
  if (bytes < 0) { exit(5);}

  Request request(std::string(rbuffer, buffer_size));
  request.parse_path();

  Response response = request.get_response();
  response.create_body();

  int response_sent = send(client_fd, response.get_body().data(), response.get_body().length(), 0);
  // ERROR CODE 6: Failure to send data to client connection
  if (response_sent < 0) { exit(6); }
  close(client_fd);
}
// === RESPONSE/REQUEST HANDLING === //


// === FLAGS === //

void check_flags(const int argc, char** argv) {
  if (argc == 1) return;
  for (int arg_idx = 1; arg_idx < argc; ++arg_idx) {
    // Currently performing only a single check for a directory flag
    if (strcmp(argv[arg_idx],"--directory") == 0 && argc >= arg_idx + 2) {
      directory = argv[arg_idx+1];
    }
  }
}
// === FLAGS === //


int main(int argc, char **argv) {
  signal(SIGINT, signalHandler);
  check_flags(argc, argv);

  // Openning socket
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  // ERROR CODE 1: Failure to create server socket
  if (server_fd < 0) { return 1; }
  
  int reuse = 1;
  // ERROR CODE 2: setsockopt failed
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) { return 2; }
  
  // Setting socket address and port
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(SOCKET_PORT);
  
  // Binding the socket to the port
  // ERROR CODE 3: Failure to bind to specified port
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) { return 3; }
  
  int connection_backlog = 5;
  // ERROR CODE 4: listen() failed
  if (listen(server_fd, connection_backlog) != 0) { return 4; }
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  // Constantly running until connections stop coming
  while (running) {
    int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
    if (client_fd >= 0) {
      std::thread client_connection(handleConnection, client_fd);
      add_thread(std::move(client_connection));
    }
  }

  join_threads();
  close(server_fd);

  return 0;
}
