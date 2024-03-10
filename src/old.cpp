#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <thread>
#include <csignal>
#include <atomic>
#include <mutex>
#include <vector>
#include <arpa/inet.h>
#include <netdb.h>

#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;
// === DIRECTORY/FILE HANDLING === //

// === DIRECTORY/FILE HANDLING === //



// === THREAD HANDLING === //
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

void signalHandler(int signal) {
  running = false;
}

// === THREAD HANDLING === //
// === RESPONSE/REQUEST HANDLING === //

constexpr std::string http_nl = "\r\n";
constexpr std::string HTTP_200_OK = "200 OK";
constexpr std::string HTTP_404_NF = "404 Not Found";
constexpr std::string HTTP_500_IE = "500 Internal Error";
constexpr int buffer_size = 1024;

class Response {
private:
  std::string http_ver, code;
  std::string body, headers, content;
  unsigned long content_length;

  void set_content(const std::string& str) {
    content = str;
    content_length = str.length();
  }

  void set_headers(const std::string& header_type) {
    headers = "Content-Type: " + header_type + http_nl;
    headers += "Content-Length: " + std::to_string(content_length) + http_nl;
  }

public:

  Response() :  http_ver{"HTTP/1.1"}, code{HTTP_404_NF}, body{""}, headers{""}, content{""}, content_length{0} { }
  
  // Highly urged to use only this function, as
  // using set_content() or set_headers() indepoendantly, may lead to bugs
  void set_content_and_headers(const std::string& cont, const std::string& header_type) {
    set_content(cont);
    set_headers(header_type);
  }

  void set_version(const std::string& version) {
    http_ver = version;
  }

  void set_code(const std::string& c) {
    code = c;
  }

  void create_body() {
    body =  http_ver + " " + code + http_nl;
    body += headers + http_nl;
    body += content;
    std::cout << body <<'\n';
  }

  std::string get_body() {
    if (body.empty()) create_body();
    return body;
  }


};

class Request {
private:
  // Start-Line
  std::string method, path, http_ver;
  // Headers
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

  void parse_path(std::string directory) {
    std::cout << "Parsing: " << path << '\n';

    if (path == "/") {
      response.set_code(HTTP_200_OK);
      return;
    }

    else if (path.find("/echo/") != std::string::npos) {
      std::string text_to_display = path.substr(6);
      response.set_content_and_headers(text_to_display, "text/plain");
      response.set_code(HTTP_200_OK);
      return;
    }
    // todo: try without fs, and sdo only by pure fstream
    else if (path.find("/files/") != std::string::npos) {
      std::string desired_file = path.substr(7);
      std::cout << "Parsing file: " << desired_file << '\n';

      fs::path full_path_to_file(directory);
      full_path_to_file /= desired_file;

      std::cout << "Full path to desired file:  " << full_path_to_file.string() << '\n';

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

      std::stringstream file_contents;
      file_contents << file.rdbuf();
      file.close();

      response.set_content_and_headers(file_contents.str(), "application/octet-stream");
      return;
    }

    // 1 is after the first slash: /_ <-
    else if(path.substr(1) == "user-agent") {
      response.set_content_and_headers(user_agent, "text/plain");
      return;
    }

    response.set_code(HTTP_404_NF);
  }

  Response get_response() { return response; }
};

// Receives Request, parses it and sends out Response
void handleConnection(int client_fd, std::string dir) {

  char rbuffer[buffer_size];
  ssize_t bytes = recv(client_fd, rbuffer, buffer_size, 0);
  if (bytes < 0) {
    std::cout << errno << "\nFAILURE TO RECEIVE REQUEST\n";
    exit(5);
  }

  std::cout << rbuffer << '\n';

  Request request(std::string(rbuffer, buffer_size));
  request.parse_path(dir);
  std::string response = request.get_response().get_body();

  int response_sent = send(client_fd, response.data(), response.length(), 0);

  if (response_sent < 0) {
    std::cout << "Error in sending requests: " << errno << '\n';
    exit(6);
  }
  else if (response_sent < response.length()) {
    std::cout << "Response was sent successfully\n";
  }
  
  close(client_fd);
}

// === RESPONSE/REQUEST HANDLING === //


int main(int argc, char **argv) {
  signal(SIGINT, signalHandler);
  
  std::string directory;
  // Checking within main, because I have no fucking idea what's going on
  if (argc >= 3 && argv[1] == "--directory") {
      directory = std::string(argv[2]);
  }

  // Opening up a socket
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
   std::cerr << "Failed to create server socket\n";
   return 1;
  }

  printf("test");
  
  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
    std::cerr << "setsockopt failed\n";
    return 2;
  }
  
  // Setting socket address and port
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(4221);
  
  // Binding the socket to the port
  if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 3;
  }
  
  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 4;
  }
  
  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);
  
  std::cout << "Waiting for a client to connect...\n";
  
  // Accepts a TCP connection and saves it to a variable to use later on
  while (running) {
    int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, (socklen_t *) &client_addr_len);
    if (client_fd >= 0) {
      std::cout << "Client connected\n";
      // Create Thread
      std::thread client_connection(handleConnection, client_fd, directory);
      // Move the thread safely
      add_thread(std::move(client_connection));
    }
  }

  // Clean up any unjoined threads
  join_threads();
  close(server_fd);

  return 0;
}