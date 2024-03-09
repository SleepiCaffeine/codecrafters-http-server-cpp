#include <iostream>

#include <cstdlib>

#include <string>

#include <cstring>

#include <unistd.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <arpa/inet.h>

#include <netdb.h>

#include <sstream>

#include <thread>

#include <vector>

void handleRequests(int connection)

{

  char buff[1024];

  while (true)

  {

    ssize_t bytes_received = recv(connection, buff, 1024, 0);

    if (bytes_received == -1)

    {

      std::cerr << "Failed to receive request\n";

    }

    else

    {

      if (bytes_received > 0)

      {

        // Convert the received buffer to a C++ string

        std::string request_string(buff, static_cast<size_t>(bytes_received));

        std::cout << "Received:\n"

                  << request_string << std::endl;

        // Process request string using std::istringstream

        std::istringstream iss(request_string);

        std::string http_response, http_method, path, http_version, host_label, host, user_agent_label, user_agent;

        bool hasUserAgent = false;

        iss >> http_method >> path >> http_version;

        if (iss.fail())

        {

          std::cerr << "Error parsing HTTP request!\n";

        }

        else

        {

          std::cout << "HTTP Method: " << http_method << std::endl;

          std::cout << "Path: " << path << std::endl;

          std::cout << "HTTP Version: " << http_version << std::endl;

        }

        // capture Host string

        iss >> host_label >> host;

        if (iss.fail())

        {

          std::cout << "no host info" << std::endl;

        }

        else

        {

          std::cout << "Host: " << host << std::endl;

        }

        // capture User-agent string

        iss >> user_agent_label >> user_agent;

        if (iss.fail())

        {

          std::cout << "no user agent info" << std::endl;

        }

        else

        {

          hasUserAgent = true;

          std::cout << "User Agent: " << user_agent << std::endl;

        }

        if (path == "/")

        {

          http_response = "HTTP/1.1 200 OK\r\n\r\n";

        }

        else if (path.find("/echo/") != std::string::npos)

        {

          size_t echoPos = path.find("/echo/");

          // Extract the substring after "/echo/"

          std::string body = path.substr(echoPos + 6); // 6 is the length of "/echo/"

          std::cout << "Body: " << body << std::endl;

          http_response = "HTTP/1.1 200 OK\r\n";

          http_response += "Content-Type: text/plain\r\n";

          http_response += "Content-Length: " + std::to_string(body.size()) + "\r\n";

          http_response += "\r\n"; // Important: empty line to separate headers from body

          http_response += body;

        }

        else if (path == "/user-agent" && hasUserAgent)

        {

          http_response = "HTTP/1.1 200 OK\r\n";

          http_response += "Content-Type: text/plain\r\n";

          http_response += "Content-Length: " + std::to_string(user_agent.size()) + "\r\n";

          http_response += "\r\n"; // Important: empty line to separate headers from body

          http_response += user_agent;

        }

        else

        {

          http_response = "HTTP/1.1 404 Not Found \r\n\r\n";

        }

        ssize_t bytes_sent = send(connection, http_response.c_str(), sizeof(buff), 0);

      }

    }

  }

}

int main(int argc, char **argv)

{

  // You can use print statements as follows for debugging, they'll be visible when running tests.

  std::cout << "Logs from your program will appear here!\n";

  // Uncomment this block to pass the first stage

  int server_fd = socket(AF_INET, SOCK_STREAM, 0);

  if (server_fd < 0)

  {

    std::cerr << "Failed to create server socket\n";

    return 1;

  }

  // Since the tester restarts your program quite often, setting REUSE_PORT

  // ensures that we don't run into 'Address already in use' errors

  int reuse = 1;

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)

  {

    std::cerr << "setsockopt failed\n";

    return 1;

  }

  struct sockaddr_in server_addr;

  server_addr.sin_family = AF_INET;

  server_addr.sin_addr.s_addr = INADDR_ANY;

  server_addr.sin_port = htons(4221);

  if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)

  {

    std::cerr << "Failed to bind to port 4221\n";

    return 1;

  }

  int connection_backlog = 5;

  if (listen(server_fd, connection_backlog) != 0)

  {

    std::cerr << "listen failed\n";

    return 1;

  }

  struct sockaddr_in client_addr;

  int client_addr_len = sizeof(client_addr);

  std::vector<std::thread> connections;

  while (true)

  {

    std::cout << "Waiting for a client to connect...\n";

    int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addr_len);

    if (client_fd >= 0)

    {

      std::cout << "Client connected\n";

      connections.push_back(std::thread(handleRequests, client_fd));

    }

  }

   close(server_fd);

  return 0;

}