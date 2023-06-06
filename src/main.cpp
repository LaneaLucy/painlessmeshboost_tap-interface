#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <netdb.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>


#include <iostream>
#include <vector>


#include <poll.h>
//#include <stdint.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000

int debug;
char *progname;

typedef unsigned char BYTE;

static const BYTE from_base64[] = {    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  62, 255,  62, 255,  63,
                                     52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 255, 255, 255,
                                    255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
                                     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255,  63,
                                    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
                                     41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255};

static const char to_base64[] =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


//std::string Base64encode(const std::vector<BYTE>& buf)
//{
//    if (buf.empty())
//        return ""; // Avoid dereferencing buf if it's empty
//    return Base64encode(&buf[0], (unsigned int)buf.size());
//}

std::string Base64encode(const BYTE* buf, unsigned int bufLen)
{
    // Calculate how many bytes that needs to be added to get a multiple of 3
    size_t missing = 0;
    size_t ret_size = bufLen;
    while ((ret_size % 3) != 0)
    {
        ++ret_size;
        ++missing;
    }

    // Expand the return string size to a multiple of 4
    ret_size = 4*ret_size/3;

    std::string ret;
    ret.reserve(ret_size);

    for (unsigned int i=0; i<ret_size/4; ++i)
    {
        // Read a group of three bytes (avoid buffer overrun by replacing with 0)
        size_t index = i*3;
        BYTE b3[3];
        b3[0] = (index+0 < bufLen) ? buf[index+0] : 0;
        b3[1] = (index+1 < bufLen) ? buf[index+1] : 0;
        b3[2] = (index+2 < bufLen) ? buf[index+2] : 0;

        // Transform into four base 64 characters
        BYTE b4[4];
        b4[0] =                            ((b3[0] & 0xfc) >> 2);
        b4[1] = ((b3[0] & 0x03) << 4) +    ((b3[1] & 0xf0) >> 4);
        b4[2] = ((b3[1] & 0x0f) << 2) +    ((b3[2] & 0xc0) >> 6);
        b4[3] = ((b3[2] & 0x3f) << 0);

        // Add the base 64 characters to the return value
        ret.push_back(to_base64[b4[0]]);
        ret.push_back(to_base64[b4[1]]);
        ret.push_back(to_base64[b4[2]]);
        ret.push_back(to_base64[b4[3]]);
    }

    // Replace data that is invalid (always as many as there are missing bytes)
    for (size_t i=0; i<missing; ++i)
        ret[ret_size - i - 1] = '=';

    return ret;
}

std::vector<BYTE> Base64decode(std::string encoded_string)
{
    // Make sure string length is a multiple of 4
    while ((encoded_string.size() % 4) != 0)
        encoded_string.push_back('=');

    size_t encoded_size = encoded_string.size();
    std::vector<BYTE> ret;
    ret.reserve(3*encoded_size/4);

    for (size_t i=0; i<encoded_size; i += 4)
    {
        // Get values for each group of four base 64 characters
        BYTE b4[4];
        b4[0] = (encoded_string[i+0] <= 'z') ? from_base64[encoded_string[i+0]] : 0xff;
        b4[1] = (encoded_string[i+1] <= 'z') ? from_base64[encoded_string[i+1]] : 0xff;
        b4[2] = (encoded_string[i+2] <= 'z') ? from_base64[encoded_string[i+2]] : 0xff;
        b4[3] = (encoded_string[i+3] <= 'z') ? from_base64[encoded_string[i+3]] : 0xff;

        // Transform into a group of three bytes
        BYTE b3[3];
        b3[0] = ((b4[0] & 0x3f) << 2) + ((b4[1] & 0x30) >> 4);
        b3[1] = ((b4[1] & 0x0f) << 4) + ((b4[2] & 0x3c) >> 2);
        b3[2] = ((b4[2] & 0x03) << 6) + ((b4[3] & 0x3f) >> 0);

        // Add the byte to the return value if it isn't part of an '=' character (indicated by 0xff)
        if (b4[1] != 0xff) ret.push_back(b3[0]);
        if (b4[2] != 0xff) ret.push_back(b3[1]);
        if (b4[3] != 0xff) ret.push_back(b3[2]);
    }

    return ret;
}







static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";


static inline bool is_base64(BYTE c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(BYTE const* buf, unsigned int bufLen) {
  std::string ret;
  int i = 0;
  int j = 0;
  BYTE char_array_3[3];
  BYTE char_array_4[4];

  while (bufLen--) {
    char_array_3[i++] = *(buf++);
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';
  }

  return ret;
}

std::vector<BYTE> base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  BYTE char_array_4[4], char_array_3[3];
  std::vector<BYTE> ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
          ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  }

  return ret;
}

const char HEX[] = {
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'a', 'b', 'c', 'd', 'e', 'f',
};

void hex(char* source, char* dest, ssize_t count)
{
  for (ssize_t i = 0; i < count; ++i) {
    unsigned char data = source[i];
    dest[2 * i] = HEX[data >> 4];
    dest[2 * i + 1] = HEX[data & 15];
  }
  dest[2 * count] = '\0';
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = (char*)"/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(std::string msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, (msg).c_str());
	vfprintf(stderr, (msg).c_str(), argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(std::string msg, ...) {

  va_list argp;
  
  va_start(argp, (msg).c_str());
  vfprintf(stderr, (msg).c_str(), argp);
  va_end(argp);
}








#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <iterator>

#include "Arduino.h"

WiFiClass WiFi;
ESPClass ESP;

#include "painlessmesh/protocol.hpp"
#include "painlessmesh/mesh.hpp"

// TODO Should not be needed anymore in versions after 1.4.9 
using namespace painlessmesh;

#include "painlessMesh.h"
#include "painlessmesh/connection.hpp"
#include "plugin/performance.hpp"


painlessmesh::logger::LogClass Log;

#undef F
#include <boost/date_time.hpp>
#include <boost/program_options.hpp>
#define F(string_literal) string_literal
namespace po = boost::program_options;

#include <iostream>
#include <iterator>
#include <limits>
#include <random>

#define OTA_PART_SIZE 1024
#include "ota.hpp"

template <class T>



// bool contains(T &v, T::value_type const value) {
bool contains(T& v, std::string const value) {
  return std::find(v.begin(), v.end(), value) != v.end();
}

std::string timeToString() {
  boost::posix_time::ptime timeLocal =
      boost::posix_time::second_clock::local_time();
  return to_iso_extended_string(timeLocal);
}

// Will be used to obtain a seed for the random number engine
static std::random_device rd;
static std::mt19937 gen(rd());

uint32_t runif(uint32_t from, uint32_t to) {
  std::uniform_int_distribution<uint32_t> distribution(from, to);
  return distribution(gen);
}


void receivedCallback( uint32_t from, std::string &msg ) {
  std::cout << "Etwas empfangen!" << std::endl;
  //mesh.sendSingle(from, msg);
}

int main(int ac, char* av[]) {
  using namespace painlessmesh;
  try {
    
    
    int tap_fd, option;
    int flags = IFF_TAP;
    char if_name[IFNAMSIZ] = "";
    int maxfd;
    uint16_t nread, nwrite, plength;
    char buffer[BUFSIZE];
    char buffer2[2*BUFSIZE + 1];
    
    
    
    size_t port = 5555;
    std::string ip = "";
    std::vector<std::string> logLevel;
    size_t nodeId = runif(0, std::numeric_limits<uint32_t>::max());
    std::string otaDir;
    double performance = 2.0;
    
    //TODO: check for nodeId to be size 10

    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "Produce this help message")(
        "tap-debug", "outputs debug information of the TAP device while running")(
        "ifname,i", po::value<std::string>(),
        "Name of interface to use (mandatory)")(
        "nodeid,n", po::value<size_t>(&nodeId),
        "Set nodeID, otherwise set to a random value")(
        "port,p", po::value<size_t>(&port), "The mesh port (default is 5555)")(
        "server,s",
        "Listen to incoming node connections. This is the default, unless "
        "--client "
        "is specified. Specify both if you want to both listen for incoming "
        "connections and try to connect to a specific node.")(
        "client,c", po::value<std::string>(&ip),
        "Connect to another node as a client. You need to provide the ip "
        "address of the node.")(
        "log,l", po::value<std::vector<std::string>>(&logLevel),
        "Only log given events to the console. By default all events are "
        "logged, this allows you to filter which ones to log. Events currently "
        "logged are: receive, connect, disconnect, change, offset and delay. "
        "This option can be specified multiple times to log multiple types of "
        "events.")("ota-dir,d", po::value<std::string>(&otaDir),
                   "Watch given folder for new firmware files.")(
        "performance", po::value<double>(&performance)->implicit_value(2.0),
        "Enable performance monitoring. Optional value is frequency (per "
        "second) to send performance monitoring packages. Default is every 2 "
        "seconds.");

    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
      std::cout << desc << std::endl;
      return 0;
    }

    if (vm.count("tap-debug")) {
      debug = 1;
    }
    
    
    if (vm.count("ifname")) {
        //cout << "Compression level was set to " << vm["compression"].as<int>() << ".\n";
        strncpy(if_name, (vm["ifname"].as<std::string>()).c_str(), IFNAMSIZ-1);
        //if_name = vm["ifname"].as<std::string>();
    } else {
      std::cout << "Must specify interface name!" << std::endl;
      return 0;
    }
    
    /* initialize tun/tap interface */
    if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
      my_err("Error connecting to tun/tap interface %s!\n", if_name);
      return 1;
    }

    do_debug("Successfully connected to interface %s\n", if_name);

    Scheduler scheduler;
    boost::asio::io_service io_service;
    painlessMesh mesh;
    Log.setLogLevel(ERROR);
    mesh.init(&scheduler, nodeId);
    
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //mesh.onReceive(&receivedCallback);
    mesh.onReceive([&mesh, &tap_fd](uint32_t nodeId, std::string& msg) {
        std::cout << "Etwas empfangen!" << std::endl;
        
        std::cerr << "base64rx: " << msg << std::endl;
        //std::cerr << "base64rxdecoded: " << Base64decode(msg) << std::endl;
        
        char bufferrx[BUFSIZE];
        std::vector<BYTE> bufferrxvec = Base64decode(msg);
        int s = bufferrxvec.size();
        memcpy(bufferrx, (char *)bufferrxvec.data(), s);
        //bufferrx = (char *)Base64decode(msg).data();
        
        char buffer2[2*BUFSIZE + 1];
        do_debug("Decodes to:\n");
        hex(bufferrx, buffer2, s);
        do_debug("%s\n", buffer2);
        
        cwrite(tap_fd, bufferrx, s);
      });
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    
    std::shared_ptr<AsyncServer> pServer;
    if (vm.count("server") || !vm.count("client")) {
      pServer = std::make_shared<AsyncServer>(io_service, port);
      painlessmesh::tcp::initServer<painlessmesh::Connection, painlessMesh>(*pServer,
                                                                  mesh);
    }

    if (vm.count("client")) {
      auto pClient = new AsyncClient(io_service);
      painlessmesh::tcp::connect<painlessmesh::Connection, painlessMesh>(
          (*pClient), boost::asio::ip::address::from_string(ip), port, mesh);
    }

    if (logLevel.size() == 0 || contains(logLevel, "receive")) {
      mesh.onReceive([&mesh](uint32_t nodeId, std::string& msg) {
        std::cout << "{\"event\":\"receive\",\"nodeTime\":"
                  << mesh.getNodeTime() << ",\"time\":\"" << timeToString()
                  << "\""
                  << ",\"nodeId\":" << nodeId << ",\"msg\":\"" << msg << "\"}"
                  << std::endl;
      });
    }
    if (logLevel.size() == 0 || contains(logLevel, "connect")) {
      mesh.onNewConnection([&mesh](uint32_t nodeId) {
        std::cout << "{\"event\":\"connect\",\"nodeTime\":"
                  << mesh.getNodeTime() << ",\"time\":\"" << timeToString()
                  << "\""
                  << ",\"nodeId\":" << nodeId
                  << ", \"layout\":" << mesh.asNodeTree().toString() << "}"
                  << std::endl;
      });
    }

    if (logLevel.size() == 0 || contains(logLevel, "disconnect")) {
      mesh.onDroppedConnection([&mesh](uint32_t nodeId) {
        std::cout << "{\"event\":\"disconnect\",\"nodeTime\":"
                  << mesh.getNodeTime() << ",\"time\":\"" << timeToString()
                  << "\""
                  << ",\"nodeId\":" << nodeId
                  << ", \"layout\":" << mesh.asNodeTree().toString() << "}"
                  << std::endl;
      });
    }

    if (logLevel.size() == 0 || contains(logLevel, "change")) {
      mesh.onChangedConnections([&mesh]() {
        std::cout << "{\"event\":\"change\",\"nodeTime\":" << mesh.getNodeTime()
                  << ",\"time\":\"" << timeToString() << "\""
                  << ", \"layout\":" << mesh.asNodeTree().toString() << "}"
                  << std::endl;
      });
    }

    if (logLevel.size() == 0 || contains(logLevel, "offset")) {
      mesh.onNodeTimeAdjusted([&mesh](int32_t offset) {
        std::cout << "{\"event\":\"offset\",\"nodeTime\":" << mesh.getNodeTime()
                  << ",\"time\":\"" << timeToString() << "\""
                  << ",\"offset\":" << offset << "}" << std::endl;
      });
    }

    if (logLevel.size() == 0 || contains(logLevel, "delay")) {
      mesh.onNodeDelayReceived([&mesh](uint32_t nodeId, int32_t delay) {
        std::cout << "{\"event\":\"delay\",\"nodeTime\":" << mesh.getNodeTime()
                  << ",\"time\":\"" << timeToString() << "\""
                  << ",\"nodeId\":" << nodeId << ",\"delay\":" << delay << "}"
                  << std::endl;
      });
    }

    if (vm.count("performance")) {
      plugin::performance::begin(mesh, performance);
    }

    if (vm.count("ota-dir")) {
      using namespace painlessmesh::plugin;
      // We probably want to temporary store the file
      // md5 -> data
      auto files = std::make_shared<std::map<std::string, std::string>>();
      // Setup task that monitors the folder for changes
      auto task =
          mesh.addTask(TASK_SECOND, TASK_FOREVER, [files, &mesh, otaDir]() {
            // TODO: Scan for change
            boost::filesystem::path p(otaDir);
            boost::filesystem::directory_iterator end_itr;
            for (boost::filesystem::directory_iterator itr(p); itr != end_itr;
                 ++itr) {
              if (!boost::filesystem::is_regular_file(itr->path())) {
                continue;
              }
              auto stat = addFile(files, itr->path(), TASK_SECOND);
              if (stat.newFile) {
                // When change, announce it, load it into files
                ota::Announce announce;
                announce.md5 = stat.md5;
                announce.role = stat.role;
                announce.hardware = stat.hw;
                announce.noPart =
                    ceil(((float)files->operator[](stat.md5).length()) /
                         OTA_PART_SIZE);
                announce.from = mesh.getNodeId();

                auto announceTask = mesh.addTask(
                    TASK_MINUTE, 60,
                    [&mesh, announce]() { mesh.sendPackage(&announce); });
                // after anounce, remove file from memory
                announceTask->setOnDisable(
                    [files, md5 = stat.md5]() { files->erase(md5); });
              }
            }
          });
      // Setup reply to data requests
      mesh.onPackage(11, [files, &mesh](protocol::Variant variant) {
        auto pkg = variant.to<ota::DataRequest>();
        // cut up the data and send it
        if (files->count(pkg.md5)) {
          auto reply =
              ota::Data::replyTo(pkg,
                                 files->operator[](pkg.md5).substr(
                                     OTA_PART_SIZE * pkg.partNo, OTA_PART_SIZE),
                                 pkg.partNo);
          mesh.sendPackage(&reply);
        } else {
          Log(ERROR, "File not found");
        }
        return true;
      });
    }
    
    uint32_t NodeId = mesh.getNodeId();
    
    do_debug("NodeId is: %lu\n", NodeId);
    
    
    struct ifreq ifr;
    int err;
    
    memset(&ifr, 0, sizeof(ifr));
    
    //ifr.ifr_name = if_name;
    //ifr.ifr_hwaddr.sa_data[0] = 0xDE;
    //ifr.ifr_hwaddr.sa_data[1] = 0xAD;
    //ifr.ifr_hwaddr.sa_data[2] = 0xBE;
    //ifr.ifr_hwaddr.sa_data[3] = 0xEF;
    //ifr.ifr_hwaddr.sa_data[4] = 0xCA;
    //ifr.ifr_hwaddr.sa_data[5] = 0xFE;
    //ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    
    if( (err = ioctl(tap_fd, SIOCGIFHWADDR, (void *)&ifr)) < 0 ) {
      perror("ioctl(SIOCGIFHWADDR)");
      close(tap_fd);
      return err;
    }
    
    //char intStr[5];// = std::to_string(NodeId);
    //intStr = std::to_string(NodeId)a.substr(0, 2);
    //do_debug("Test %s\n", std::to_string(NodeId));
    /*std::cout << std::to_string(NodeId).substr(0, 2) << std::endl;
    std::cout << std::to_string(NodeId).substr(2, 2) << std::endl;
    std::cout << std::to_string(NodeId).substr(4, 2) << std::endl;
    std::cout << std::to_string(NodeId).substr(6, 2) << std::endl;
    std::cout << std::to_string(NodeId).substr(8, 2) << std::endl;
    */
    //do_debug("00:%s:%s:%s:%s:%s\n", std::to_string(NodeId).substr(0, 2), std::to_string(NodeId).substr(2, 2), std::to_string(NodeId).substr(4, 2), std::to_string(NodeId).substr(6, 2), std::to_string(NodeId).substr(8, 2));
    
/*
    std::string s = "00";
    s.append(std::to_string(NodeId));
    std::cout << s << std::endl;
    char * p;
    long n = strtol( s.c_str(), & p, 16 ); 
    if ( * p != 0 ) {  
        std::cout << "not a number" << std::endl;
    }    else {  
        std::cout << n << std::endl;
    }
    
    std::string temp_str=std::to_string(n); //converting number to a string
    char const* number_array= temp_str.c_str();
*/
    
    ifr.ifr_hwaddr.sa_data[0] = 0x00;
    for (int i = 0; i < 6; i++) {
      char * p;
      long n = strtol( std::to_string(NodeId).substr(i * 2, 2).c_str(), & p, 16 ); 
      if ( * p != 0 ) {  
          std::cout << "not a number" << std::endl;
          return 1;
      }
      ifr.ifr_hwaddr.sa_data[i + 1] = n;
    }

    
    
/*    //int x;
    char bytes[sizeof n];
    std::copy(static_cast<const char*>(static_cast<const void*>(&n)),
              static_cast<const char*>(static_cast<const void*>(&n)) + sizeof n,
              bytes);
    
    ifr.ifr_hwaddr.sa_data = bytes;
*/
    
    
    //ifr.ifr_hwaddr.sa_data[0] = 0x00;
    //ifr.ifr_hwaddr.sa_data[1] = number_array[0];
    //ifr.ifr_hwaddr.sa_data[2] = stoi(std::to_string(NodeId).substr(2, 2));
    //ifr.ifr_hwaddr.sa_data[3] = stoi(std::to_string(NodeId).substr(4, 2));
    //ifr.ifr_hwaddr.sa_data[4] = stoi(std::to_string(NodeId).substr(6, 2));
    //ifr.ifr_hwaddr.sa_data[5] = stoi(std::to_string(NodeId).substr(8, 2));
    
    if( (err = ioctl(tap_fd, SIOCSIFHWADDR, (void *)&ifr)) < 0 ) {
      perror("ioctl(SIOCSIFHWADDR)");
      close(tap_fd);
      return err;
    }
    
    struct pollfd  fds[1];
    
    fds[0].fd = tap_fd;
    fds[0].events = POLLIN;
    
    
    uint32_t srcmacid;
    //char * srcmacchar;
    uint32_t dstmacid;
    
    struct ether_header *eh = (struct ether_header *) buffer;
    
    
    while (true) {
      usleep(1000);  // Tweak this for acceptable cpu usage
      mesh.update();
      io_service.poll();
      poll(fds,1,-1);
      if (fds[0].revents & POLLIN) {
        // tap to mesh
        //printf("POLLING");
        nread = cread(tap_fd, buffer, BUFSIZE);
        //tap2net++;
        do_debug("TAP: Read %d bytes from the tap interface\n", nread);
        
        //memcpy(srcmac, buffer + 0 /* Offset */, 6 /* Length */);
        //memcpy(dstmac, buffer + 6 /* Offset */, 6 /* Length */);
        
        
        //std::string bufferstr = buffer;
        //bufferstr.copy(srcmac, 6, 0);
        //bufferstr.copy(dstmac, 6, 6);
        
        
        //do_debug("TAP: Read srcmac %02X \n", srcmac);
        //do_debug("TAP: Read dstmac %02X \n", dstmac);
        
        
        do_debug("Here is the message:\n");
        hex(buffer, buffer2, nread);
        do_debug("%s\n", buffer2);
        
        printf("Destination MAC: %x:%x:%x:%x:%x:%x\n",
						eh->ether_dhost[0],
						eh->ether_dhost[1],
						eh->ether_dhost[2],
						eh->ether_dhost[3],
						eh->ether_dhost[4],
						eh->ether_dhost[5]);
        
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
						eh->ether_shost[0],
						eh->ether_shost[1],
						eh->ether_shost[2],
						eh->ether_shost[3],
						eh->ether_shost[4],
						eh->ether_shost[5]);
        
        if ((not (eh->ether_dhost[0] == 0xff && eh->ether_dhost[1] == 0xff && eh->ether_dhost[2] == 0xff && eh->ether_dhost[3] == 0xff && eh->ether_dhost[4] == 0xff && eh->ether_dhost[5] == 0xff)) && (eh->ether_dhost[0] != 0x00)) {
          do_debug("first dstMAC byte dont match 0x00 and not broadcast. SKIP\n");
          continue;
        }
        
        //snprintf(srcmacchar, "%02x%02x%02x%02x%02x%02x", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
        
        char *buf;
        size_t sz;
        sz = snprintf(NULL, 0, "%02x%02x%02x%02x%02x%02x", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
        buf = (char *)malloc(sz + 1); /* make sure you check for != NULL in real code */
        snprintf(buf, sz+1, "%02x%02x%02x%02x%02x%02x", eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
        
        do_debug("dstMAC char: %s \n", buf);
        dstmacid =  std::atoi(buf);
        
        
        sz = snprintf(NULL, 0, "%02x%02x%02x%02x%02x%02x", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
        buf = (char *)malloc(sz + 1); /* make sure you check for != NULL in real code */
        snprintf(buf, sz+1, "%02x%02x%02x%02x%02x%02x", eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2], eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
        
        do_debug("srcMAC char: %s \n", buf);
        srcmacid =  std::atoi(buf);
        
        
        
        //do_debug("srcMAC char: ");
        //std::cout << buf << std::endl;
        
        
        //srcmacid = (uint32_t)srcmacchar; 
        //memcpy(&srcmacid, buf, 4);
        //srcmacid =  std::atoi(buf);
        
        //dstmac = eh->ether_dhost;
        //do_debug("TAP: Read dstmac %02X \n", eh->ether_dhost);
        
        do_debug("dstMAC number: %lu \n", dstmacid);
        do_debug("srcMAC number: %llu \n", srcmacid);
        
        
        //return 0;
        
        
        //BYTE buff[BUFSIZE] = &buffer;
        
        //do_debug("data tap rx: %s \n", buffer);
        
        std::cerr << "base64tx: " << Base64encode((unsigned char *)&buffer, nread) << std::endl;
        
        
        if (eh->ether_dhost[0] == 0xff && eh->ether_dhost[1] == 0xff && eh->ether_dhost[2] == 0xff && eh->ether_dhost[3] == 0xff && eh->ether_dhost[4] == 0xff && eh->ether_dhost[5] == 0xff) {
          do_debug("BROADCAST\n");
          //mesh.sendBroadcast(buffer);
          mesh.sendBroadcast(Base64encode((unsigned char *)&buffer, nread), true); // ###################### DEBUG #########################
	} else {
	  mesh.sendSingle(dstmacid, Base64encode((unsigned char *)&buffer, nread));
	}
        
      }
      // mesh to tap
    }
  } catch (std::exception& e) {
    std::cerr << "error: " << e.what() << std::endl;
    ;
    return 1;
  } catch (...) {
    std::cerr << "Exception of unknown type!" << std::endl;
    ;
  }

  return 0;
}
