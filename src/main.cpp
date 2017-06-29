#include <iostream>
#include <string>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lib/utils/Time.h"
#include "lib/utils/CmdlineOption.h"
#include "lib/utils/RichTxt.h"
#include "lib/net/Sniffer.h"

using namespace std;

static const string g_softname(RichTxt::bold_on + "spice protocol sniffer" + RichTxt::bold_off);
static const string g_version("0.0.1");
static const string g_myemail("@@@@@@");
static const string g_myemail_color(RichTxt::bold_on + RichTxt::foreground_green + g_myemail + RichTxt::reset_all);
static const string g_mywebspace("@@@@@@@");
static const string g_mywebspace_color(RichTxt::bold_on + RichTxt::foreground_green + g_mywebspace + RichTxt::reset_all);

static void showHelpInfo (void)
{
    cout << endl;
    cout << g_softname
         << " is a sniffer about spice protocol " << endl
         << "It's easy and simple to use. Usually, you could issue it as follow: " << endl
         << "  $ spice_sniffer --serverip 127.0.0.1 --serverport 5901 --f ~/Downloads" << endl;

    cout << endl;
    cout << "  --help" << endl
         << "  Show this help infomation what you are seeing. " << endl;

    cout << endl;
    cout << "  --version" << endl
         << "  Show current version. " << endl;

    cout << endl;
    cout << "  --dev" << endl
         << "  You should set the nic name. " << endl;

    cout << endl;
    cout << "  --sip" << endl
         << "  You should set the spice server ip address. " << endl;

    cout << endl;
    cout << "  --sport" << endl
         << "  you should set the virtual machine port number. " << endl
         << "  The default port is 5901." << endl;

    cout << endl;
    cout << "  --f" << endl
         << "  You can set output file " << endl
         << "  The default is console. " << endl;

    cout << endl;
    cout << "  That's all. Thanks for your use. " << endl << endl;
}

static void showVersionInfo (void)
{
    cout << "spice_sniffer version " << g_version << endl
         << "email " << g_myemail << endl
         << "webspace " << g_mywebspace << endl << endl;
}


int main (int argc, char* argv[])
{
	CmdlineOption cmdline_options((unsigned)argc, argv);
	vector<string> cmdline_arguments_list;

	if (cmdline_options.hasOption("--help")) 
	{
        showHelpInfo();
        return(EXIT_SUCCESS);
    }

    if (cmdline_options.hasOption("--version")) 
    {
        showVersionInfo();
        return(EXIT_SUCCESS);
    }

    //cout << "Your command arguments: " << endl;

    string device;
    cmdline_arguments_list = cmdline_options.getArgumentsList("--dev");
    if (!cmdline_arguments_list.empty()) {
        device = cmdline_arguments_list[0];
    }
    cout << device << endl;


    string serverip;
    cmdline_arguments_list = cmdline_options.getArgumentsList("--sip");
    if (!cmdline_arguments_list.empty()) {
        serverip = cmdline_arguments_list[0];
    }
    cout << serverip << endl;

    int serverport;
    cmdline_arguments_list = cmdline_options.getArgumentsList("--sport");
    if (!cmdline_arguments_list.empty()) {
        serverport = atoi(cmdline_arguments_list[0].c_str());
    }
    cout << serverport << endl;

    string output_file_path;
    cmdline_arguments_list = cmdline_options.getArgumentsList("--f");
    if (!cmdline_arguments_list.empty()) {
        output_file_path = cmdline_arguments_list[0];
    }
    cout << output_file_path << endl;
    
    int ret;
    Sniffer spice_sniffer(device, serverip, serverport);
    ret = spice_sniffer.CreateRawSocket();
    if(ret)
    {
        cout << "error" << endl;
        return 0;
    }
    spice_sniffer.ParsePackage();
    cout << "the end" << endl;
    return 0;
}
