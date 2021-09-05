/**********************************************************************************
	First Growtopia Private Server made with ENet.
	Copyright (C) 2018  Growtopia Noobs

	Server Name: Growtopia
	Owner: Time
**********************************************************************************/


#include "stdafx.h"
#include <iostream>
#include <regex>
#include <experimental/filesystem>
#include "enet/enet.h"
#include <string>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#endif
#ifdef __linux__
#include <stdio.h>
char _getch() {
	return getchar();
}
#endif
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#ifdef _WIN32
#include "bcrypt.h"
#include "playmods.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.cpp"
#else
#include "bcrypt.h"
#include "bcrypt.cpp"
#include "crypt_blowfish/crypt_gensalt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.h"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.h"
#endif
#include <thread> // TODO
#include <mutex> // TODO

#pragma warning(disable : 4996)

using namespace std;
using json = nlohmann::json;
string newslist = "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds (and accounts)`` might be deleted at any time if database issues appear (once per day or week).|left|4|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new account updates, which will cause database incompatibility.|left|4|\nadd_spacer|small|\n\nadd_url_button||``Watch: `1Watch a video about GT Private Server``|NOFLAGS|https://www.youtube.com/watch?v=_3avlDDYBBY|Open link?|0|0|\nadd_url_button||``Channel: `1Watch Growtopia Noobs' channel``|NOFLAGS|https://www.youtube.com/channel/UCLXtuoBlrXFDRtFU8vPy35g|Open link?|0|0|\nadd_url_button||``Items: `1Item database by Nenkai``|NOFLAGS|https://raw.githubusercontent.com/Nenkai/GrowtopiaItemDatabase/master/GrowtopiaItemDatabase/CoreData.txt|Open link?|0|0|\nadd_url_button||``Discord: `1GT Private Server Discord``|NOFLAGS|https://discord.gg/8WUTs4v|Open the link?|0|0|\nadd_quick_exit|\n\nend_dialog|gazette|Close||";

//#define TOTAL_LOG
#define REGISTRATION
#include <signal.h>
#ifdef __linux__
#include <cstdint>
typedef unsigned char BYTE;
typedef unsigned char byte;
typedef unsigned char __int8;
typedef unsigned short __int16;
typedef unsigned int DWORD;
#endif
ENetHost* server;
int cId = 1;
int saveTotal = 0;
BYTE* itemsDat = 0;
int itemsDatSize = 0;
bool GlobalMaintenance = false;
bool restartForUpdate = false;
long long int lastIPWait = 0;
int lastIPLogon;
int IPNoLoop;
long long int NoSpam = 0;
long long int NoLoop = 0;
//Linux equivalent of GetLastError
#ifdef __linux__
string GetLastError() {
	return strerror(errno);
}
//Linux has no byteswap functions.
ulong _byteswap_ulong(ulong x)
{
	// swap adjacent 32-bit blocks
	//x = (x >> 32) | (x << 32);
	// swap adjacent 16-bit blocks
	x = ((x & 0xFFFF0000FFFF0000) >> 16) | ((x & 0x0000FFFF0000FFFF) << 16);
	// swap adjacent 8-bit blocks
	return ((x & 0xFF00FF00FF00FF00) >> 8) | ((x & 0x00FF00FF00FF00FF) << 8);
}
#endif

//configs
int configPort = 17091;
string configCDN = "0098/CDNContent77/cache/";


/***bcrypt***/

bool verifyPassword(string password, string hash) {
	int ret;

	ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);

	return !ret;
}

bool has_only_digits(const string str)
{
	return str.find_first_not_of("0123456789") == std::string::npos;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;

	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket* packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data + 4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}

	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string& delimiter, const string& str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i < strleng)
	{
		int j = 0;
		while (i + j < strleng && j < delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct gamepacket_t
{
private:
	int index = 0;
	int len = 0;
	byte* packet_data = new byte[61];

public:
	gamepacket_t(int delay = 0, int NetID = -1) {

		len = 61;
		int MessageType = 0x4;
		int PacketType = 0x1;
		int CharState = 0x8;

		memset(packet_data, 0, 61);
		memcpy(packet_data, &MessageType, 4);
		memcpy(packet_data + 4, &PacketType, 4);
		memcpy(packet_data + 8, &NetID, 4);
		memcpy(packet_data + 16, &CharState, 4);
		memcpy(packet_data + 24, &delay, 4);
	};
	~gamepacket_t() {
		delete[] packet_data;
	}

	void Insert(string a) {
		byte* data = new byte[len + 2 + a.length() + 4];
		memcpy(data, packet_data, len);
		delete[] packet_data;
		packet_data = data;
		data[len] = index;
		data[len + 1] = 0x2;
		int str_len = a.length();
		memcpy(data + len + 2, &str_len, 4);
		memcpy(data + len + 6, a.data(), str_len);
		len = len + 2 + a.length() + 4;
		index++;
		packet_data[60] = (byte)index;
	}
	void Insert(int a) {
		byte* data = new byte[len + 2 + 4];
		memcpy(data, packet_data, len);
		delete[] packet_data;
		packet_data = data;
		data[len] = index;
		data[len + 1] = 0x9;
		memcpy(data + len + 2, &a, 4);
		len = len + 2 + 4;
		index++;
		packet_data[60] = (byte)index;
	}
	void Insert(unsigned int a) {
		byte* data = new byte[len + 2 + 4];
		memcpy(data, packet_data, len);
		delete[] packet_data;
		packet_data = data;
		data[len] = index;
		data[len + 1] = 0x5;
		memcpy(data + len + 2, &a, 4);
		len = len + 2 + 4;
		index++;
		packet_data[60] = (byte)index;
	}
	void Insert(float a) {
		byte* data = new byte[len + 2 + 4];
		memcpy(data, packet_data, len);
		delete[] packet_data;
		packet_data = data;
		data[len] = index;
		data[len + 1] = 0x1;
		memcpy(data + len + 2, &a, 4);
		len = len + 2 + 4;
		index++;
		packet_data[60] = (byte)index;
	}
	void Insert(float a, float b) {
		byte* data = new byte[len + 2 + 8];
		memcpy(data, packet_data, len);
		delete[] packet_data;
		packet_data = data;
		data[len] = index;
		data[len + 1] = 0x3;
		memcpy(data + len + 2, &a, 4);
		memcpy(data + len + 6, &b, 4);
		len = len + 2 + 8;
		index++;
		packet_data[60] = (byte)index;
	}
	void Insert(float a, float b, float c) {
		byte* data = new byte[len + 2 + 12];
		memcpy(data, packet_data, len);
		delete[] packet_data;
		packet_data = data;
		data[len] = index;
		data[len + 1] = 0x4;
		memcpy(data + len + 2, &a, 4);
		memcpy(data + len + 6, &b, 4);
		memcpy(data + len + 10, &c, 4);
		len = len + 2 + 12;
		index++;
		packet_data[60] = (byte)index;
	}
	void CreatePacket(ENetPeer* peer) {
		ENetPacket* packet = enet_packet_create(packet_data, len, 1);
		enet_peer_send(peer, 0, packet);
	}
};
struct GamePacket
{
	BYTE* data;
	int len;
	int indexes;
};
GamePacket appendFloat(GamePacket p, float val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 1;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 8];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 3;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	p.len = p.len + 2 + 8;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2, float val3)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 12];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 4;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	memcpy(n + p.len + 10, &val3, 4);
	p.len = p.len + 2 + 12;
	p.indexes++;
	return p;
}

GamePacket appendInt(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 9;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendIntx(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 5;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendString(GamePacket p, string str)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 2;
	int sLen = str.length();
	memcpy(n + p.len + 2, &sLen, 4);
	memcpy(n + p.len + 6, str.c_str(), sLen);
	p.len = p.len + 2 + str.length() + 4;
	p.indexes++;
	return p;
}

GamePacket createPacket()
{
	BYTE* data = new BYTE[61];
	string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
		if (asdf.length() > 61 * 2) throw 0;
	}
	GamePacket packet;
	packet.data = data;
	packet.len = 61;
	packet.indexes = 0;
	return packet;
}

GamePacket packetEnd(GamePacket p)
{
	BYTE* n = new BYTE[p.len + 1];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	char zero = 0;
	memcpy(p.data + p.len, &zero, 1);
	p.len += 1;
	*(int*)(p.data + 56) = p.indexes;//p.len-60;//p.indexes;
	*(BYTE*)(p.data + 60) = p.indexes;
	//*(p.data + 57) = p.indexes;
	return p;
}

//Player Start here

class Player {
public:
	static void OnConsoleMessage(ENetPeer* peer, string text);
	static void OnTalkBubble(ENetPeer* peer, int netID, string text, int chatColor, bool isOverlay);
	static void OnAddNotification(ENetPeer* peer, string text, string audiosound, string interfaceimage);
	static void OnStartAcceptLogon(ENetPeer* peer, int itemdathash);
	static void OnRemove(ENetPeer* peer, int netID);
	static void OnSendToServer(ENetPeer* peer, int userID, int token, string ip, int port, string doorId, int lmode); // no need other args, sub servers done&working already... using fake data etc.
	static void SendTileAnimation(ENetPeer* peer, int x, int y, int causedBy, int tile);
	static void PlayAudio(ENetPeer* peer, string audioFile, int delayMS);
	static void showWrong(ENetPeer* peer, string itemFind, string listFull);
	static void OnZoomCamera(ENetPeer* peer, float value1, int value2);
	static void SmoothZoom(ENetPeer* peer);
	static void OnRaceStart(ENetPeer* peer, int netID);
	static void OnRaceEnd(ENetPeer* peer, int netID);
	static void OnSetCurrentWeather(ENetPeer* peer, int weather);
	static void OnPlayPositioned(ENetPeer* peer, string audiofile, int netID, bool broadcastInWorld, ENetPacket* pk);
	static void OnCountdownStart(ENetPeer* peer, int netID, int time, int score);
	static void OnCountdownUpdate(ENetPeer* peer, int netID, int score);
	static void OnCountdownEnd(ENetPeer* peer);
	static void OnStartTrade(ENetPeer* peer, string displayName, int netID);
	static void OnTextOverlay(ENetPeer* peer, string text);
	static void OnForceTradeEnd(ENetPeer* peer);
	static void OnFailedToEnterWorld(ENetPeer* peer);
	static void OnNameChanged(ENetPeer* peer, int netID, string name);
	static void OnTradeStatus(ENetPeer* peer, int netID, string statustext, string items, string locked);
	static void OnDialogRequest(ENetPeer* peer, string args);
	static void OnKilled(ENetPeer* peer, int netID);
	static void OnSetFreezeState(ENetPeer* peer, int state, int netID);
	static void OnSetPos(ENetPeer* peer, int netID, int x, int y, int delay);
	static void OnFlagMay2019(ENetPeer* peer, int state, int netID);
	static void OnBillboardChange(ENetPeer* peer, int netID); //testing billboards
	static void SendTilePickup(ENetPeer* peer, int itemid, int netID, float x, float y, int itemcount, int itemamount);
	static void OnInvis(ENetPeer* peer, int state, int netID);
	static void OnChangeSkin(ENetPeer* peer, int skinColor, int netID);
	static void SetRespawnPos(ENetPeer* peer, int posX, int posY, int netID);
	static void OnSetBux(ENetPeer* peer, int gems, int accountstate);
	static void OnParticleEffect(ENetPeer* peer, int effect, float x, float y, int delay);
	static void SetHasGrowID(ENetPeer* peer, int status, string username, string password);
	static void OnSpawn(ENetPeer* peer, int netID, int userID, int posX, int posY, string name, string country, int invis, int modstate, int supermodstate);
	static void OnReconnect(ENetPeer* peer);
	static void OnRedirectServer(ENetPeer* peer, string ip, int mode);
	static void OnItemEffect(ENetPeer* peer, int itemid, int netID, int x, int y);
	static void OnInitialLogonAccepted(ENetPeer* peer, int itemsdathash);
	static void Ping(ENetPeer* peer);
};

void Player::OnFailedToEnterWorld(ENetPeer* peer) {
	GamePacket p = packetEnd(appendIntx(appendString(createPacket(), "OnFailedToEnterWorld"), 1));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
void Player::showWrong(ENetPeer* peer, string itemFind, string listFull) {

	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFind item: " + itemFind + "``|left|206|\nadd_spacer|small|\n" + listFull + "add_textbox|Enter a word below to find the item|\nadd_text_input|item|Item Name||30|\nend_dialog|findid|Cancel|Find the item!|\n"));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}
void Player::OnInvis(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), state));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}


void OnInvisV2(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnInvis"), state));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnTextOverlay(ENetPeer* peer, string text) {
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), text));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnKilled(ENetPeer* peer, int netID) {
	GamePacket p = packetEnd(appendString(createPacket(), "OnKilled"));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::SetRespawnPos(ENetPeer* peer, int posX, int posY, int netID) {
	GamePacket p22 = packetEnd(appendInt(appendString(createPacket(), "SetRespawnPos"), posX + posY)); // (world->width * posY)
	memcpy(p22.data + 8, &netID, 4);
	ENetPacket* packet22 = enet_packet_create(p22.data,
		p22.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet22);
	delete p22.data;
}



void Player::OnStartAcceptLogon(ENetPeer* peer, int itemdathash) {
	GamePacket p = packetEnd(appendString(appendString(appendString(appendString(appendInt(appendString(createPacket(),
		"OnSuperMainStartAcceptLogonHrdxs47254722215a"), itemdathash), "growtopia3.com"), "a/cache/"),
		"cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster"),
		"proto=80|choosemusic=audio/mp3/theme4.mp3|active_holiday=0|"));

	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnSetFreezeState(ENetPeer* peer, int state, int netID) {
	GamePacket p = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), state));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnZoomCamera(ENetPeer* peer, float value1, int value2) {
	GamePacket p = packetEnd(appendIntx(appendFloat(appendString(createPacket(), "OnZoomCamera"), value1), value2));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

struct PlayerMoving {
	int packetType;
	int netID;
	float x;
	float y;
	int characterState;
	int plantingTree;
	float XSpeed;
	float YSpeed;
	int punchX;
	int punchY; int secondnetID;
};





struct TileExtra {
	int packetType;
	int characterState;
	float objectSpeedX;
	int punchX;
	int punchY;
	int charStat;
	int blockid;
	int visual;
	int signs;
	int backgroundid;
	int displayblock;
	int time;
	int netID;
	int weatherspeed;
	int bpm;
};
void sendnews(ENetPeer* peer)
{
	try {
		std::ifstream ifs("news.txt");
		std::string content((std::istreambuf_iterator<char>(ifs)),
			(std::istreambuf_iterator<char>()));
		Player::OnDialogRequest(peer, content);
	}
	catch (std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
	catch (const std::out_of_range& e) {
		cout << "[try-catch ERROR]: Out of Range error in id == 'wk'" << endl;
	}
	catch (...) {
		cout << "reading file violation" << endl;
	}
}

void SendPacketRaw1(int a1, void* packetData, size_t packetDataSize, void* a4, ENetPeer* peer, int packetFlag, int delay)
{
	ENetPacket* p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE*)packetData + 12) & 8)
		{

			p = enet_packet_create(0, packetDataSize + *((DWORD*)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char*)p->data + 4, packetData, packetDataSize);
			memcpy((char*)p->data + packetDataSize + 4, a4, *((DWORD*)packetData + 13));
			int deathFlag = 0x19;
			memcpy(p->data + 24, &delay, 4);
			memcpy(p->data + 56, &deathFlag, 4);
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char*)p->data + 4, packetData, packetDataSize);
			int deathFlag = 0x19;
			memcpy(p->data + 24, &delay, 4);
			memcpy(p->data + 56, &deathFlag, 4);
			enet_peer_send(peer, 0, p);
		}
	}
	delete (char*)packetData;
}

struct ItemSharedUID {
	int actual_uid = 1;
	int shared_uid = 1;
};

struct InventoryItem {
	__int16 itemID;
	__int8 itemCount;
};

struct PlayerInventory {
	vector<InventoryItem> items;
	int inventorySize = 250;
};

#define cloth0 cloth_hair
#define cloth1 cloth_shirt
#define cloth2 cloth_pants
#define cloth3 cloth_feet
#define cloth4 cloth_face
#define cloth5 cloth_hand
#define cloth6 cloth_back
#define cloth7 cloth_mask
#define cloth8 cloth_necklace
#define cloth9 cloth_ances
#define STR16(x, y) (*(uint16_t*)(&(x)[(y)]))
#define STRINT(x, y) (*(int*)(&(x)[(y)]))

//
struct ServerPermissions {
	bool editServer = false;
	bool freeItems = false;
};
//

struct PlayerInfo {
	bool isIn = false;
	int xp = 0;
	bool joinguild = false;
	int effect = 8421376;
	int characterState = 0;
	int netID;
	vector<string> friendinfo;
	vector<string> createfriendtable;
	string lastfriend = "";
	string lastFrn = "";
	string lastFrnName = "";
	string lastFrnWorld = "";
	string lastInfo = "";
	int level = 1;
	int OnlineNow = 0;
	string sendToWorld = "";
	int embed_tileX;
	int embed_tileY;
	int respawnX;
	int respawnY;
	bool bypass_underscore = false;
	string AAP = "";
	string displayNameBackup = "";
	bool fastPunch = false;
	int lastdropitemcount = 0;
	int lastdropitem = 0;
	int droppeditemcount = 0;
	int lasttrashitem = 0;
	int lasttrashitemcount = 0;
	int lastUserID = 0;
	string lastUser = "";
	bool RotatedLeft = false;
	bool AAPfirst = false;
	bool isnicked = false;
	int attempt = 0;
	bool haveGrowId = false;
	bool ischeck = false;
	int checkx = 0;
	int checky = 0;
	bool banned = false;
	bool cursed = false;
	string tankIDName = "";
	string tankIDPass = "";
	string requestedName = "";
	string rawName = "";
	string displayName = "";
	string country = "";
	string userID = "";

	string gameversion = "";
	string rid = "none";
	string gid = "none";
	string aid = "none";
	string vid = "none";
	string wkid = "";
	string metaip = "";
	string hash2 = "";
	string hash = "";
	string fhash = "";
	string mac = "none";
	string token = "";
	string user = "";
	string deviceversion = "";
	string doorID = "";
	string cbits = "";
	string lmode = "";
	string gdpr = "";
	string f = "";
	string fz = "";
	string hpid = "";
	string platformID = "";
	string player_age = "1";
	string sid = "none";
	string zf = "";
	//strre
	string lock_tab_string = "";
	string legendary_tab_string = "";
	string storeItemMenu = "";

	int invis = 0;
	int adminLevel = 0;
	string currentWorld = "EXIT";
	bool radio = true;
	int x;
	int y;
	int x1;
	int y1;
	string personal_note = "";
	int gem = 0;

	bool isRotatedLeft = false;
	string charIP = "";
	bool isUpdating = false;
	bool GlobalMaintenance = false;
	bool joinClothesUpdated = false;

	bool hasLogon = false;

	bool taped = false;
	//useless stuff
	int maxItems = 11103;

	//Store
	string store_itemBuyName = "";
	string store_itemPrice = "";
	string store_itemName = "";
	string store_itemID = "";
	bool store_Confirm = false;
	//store
	int cloth_hair = 0; // 0
	int cloth_shirt = 0; // 1
	int cloth_pants = 0; // 2
	int cloth_feet = 0; // 3
	int cloth_face = 0; // 4
	int cloth_hand = 0; // 5
	int cloth_back = 0; // 6
	int cloth_mask = 0; // 7
	int cloth_necklace = 0; // 8
	int cloth_ances = 0; // 9

	bool canWalkInBlocks = false; // 1
	bool canDoubleJump = false; // 2
	bool isInvisible = false; // 4
	bool noHands = false; // 8
	bool noEyes = false; // 16
	bool noBody = false; // 32
	bool devilHorns = false; // 64
	bool goldenHalo = false; // 128
	bool isFrozen = false; // 2048
	bool isCursed = false; // 4096
	bool isDuctaped = false; // 8192
	bool bantape = false; // 8192
	bool haveCigar = false; // 16384
	bool isShining = false; // 32768
	bool isZombie = false; // 65536
	bool isHitByLava = false; // 131072
	bool haveHauntedShadows = false; // 262144
	bool haveGeigerRadiation = false; // 524288
	bool haveReflector = false; // 1048576
	bool isEgged = false; // 2097152
	bool havePineappleFloag = false; // 4194304
	bool haveFlyingPineapple = false; // 8388608
	bool haveSuperSupporterName = false; // 16777216
	bool haveBluename = false; // 16777216
	bool haveSupperPineapple = false; // 33554432

	bool isGhost = false;
	//bool 
	int skinColor = 0x8295C3FF; //normal SKin color like gt!

	PlayerInventory inventory;
	short currentInventorySize = 0;
	long long int lastSB = 0;
	long long int packetsec = 0;
	int packetinsec = 0;

	int delay_SaveBuilding = 0;
	//hacky dropped item stuff :(
	vector<ItemSharedUID> item_uids;
	int last_uid = 1;
};
void UpdateOnline() {
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		((PlayerInfo*)(currentPeer->data))->OnlineNow++;
	}
}
BYTE* packPlayerMoving(PlayerMoving* dataStruct)
{
	BYTE* data = new BYTE[56];
	for (int i = 0; i < 56; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 4, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 20, &dataStruct->plantingTree, 4);
	memcpy(data + 24, &dataStruct->x, 4);
	memcpy(data + 28, &dataStruct->y, 4);
	memcpy(data + 32, &dataStruct->XSpeed, 4);
	memcpy(data + 36, &dataStruct->YSpeed, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	return data;
}
bool isHere(ENetPeer* peer, ENetPeer* peer2)
{
	return ((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(peer2->data))->currentWorld;
}

void playerRespawn(ENetPeer* peer, bool isDeadByTile) {
	int netID = ((PlayerInfo*)(peer->data))->netID;
	if (isDeadByTile == false) {
		Player::OnKilled(peer, ((PlayerInfo*)(peer->data))->netID);
	}
	GamePacket p2x = packetEnd(appendInt(appendString(createPacket(), "OnSetFreezeState"), 0));
	memcpy(p2x.data + 8, &netID, 4);
	int respawnTimeout = 2000;
	int deathFlag = 0x19;
	memcpy(p2x.data + 24, &respawnTimeout, 4);
	memcpy(p2x.data + 56, &deathFlag, 4);
	ENetPacket* packet2x = enet_packet_create(p2x.data,
		p2x.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2x);
	delete p2x.data;
	Player::OnSetFreezeState(peer, 2, netID);
	GamePacket p2 = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), ((PlayerInfo*)(peer->data))->respawnX, ((PlayerInfo*)(peer->data))->respawnY));
	memcpy(p2.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
	respawnTimeout = 2000;
	memcpy(p2.data + 24, &respawnTimeout, 4);
	memcpy(p2.data + 56, &deathFlag, 4);
	ENetPacket* packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
	delete p2.data;
	GamePacket p2a = packetEnd(appendString(appendString(createPacket(), "OnPlayPositioned"), "audio/teleport.wav"));
	memcpy(p2a.data + 8, &netID, 4);
	respawnTimeout = 2000;
	memcpy(p2a.data + 24, &respawnTimeout, 4);
	memcpy(p2a.data + 56, &deathFlag, 4);
	ENetPacket* packet2a = enet_packet_create(p2a.data,
		p2a.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2a);
	delete p2a.data;
}
void Player::OnPlayPositioned(ENetPeer* peer, string audiofile, int netID, bool broadcastInWorld, ENetPacket* pk) // packet only externally used when broadcasting / sending to multiple players to reduce memory leaks / cpu usage cuz we dont want to loop creating the packet for each player that would be insanely stupid.
{
	if (broadcastInWorld) {
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, pk);
			}
		}
	}
	else
	{
		auto p = packetEnd(appendString(appendString(createPacket(), "OnPlayPositioned"), audiofile));
		memcpy(p.data + 8, &netID, 4);
		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}

void effectbarrel(ENetPeer* peer, float x, float y, int netid, int delays) {

	Player::PlayAudio(peer, "audio/explode.wav", delays);
	PlayerMoving data;
	data.packetType = 17;
	data.netID = netid;
	data.x = x;
	data.y = y;
	data.characterState = 0;
	data.plantingTree = 0;
	data.XSpeed = 4;
	data.YSpeed = 1;
	data.punchX = 0;
	data.punchY = 0;
	data.secondnetID = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			SendPacketRaw1(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE, delays);
		}
	}
}
void pullEffect(ENetPeer* peer, float x, float y, int netid, int delays) {

	PlayerMoving data;
	data.packetType = 17;
	data.netID = netid;
	data.x = x;
	data.y = y;
	data.characterState = 0;
	data.plantingTree = 0;
	data.XSpeed = 2;
	data.YSpeed = 1;
	data.punchX = 0;
	data.punchY = 0;
	data.secondnetID = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			SendPacketRaw1(4, packPlayerMoving(&data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE, delays);
		}
	}
}
void Player::OnTalkBubble(ENetPeer* peer, int netID, string text, int chatColor, bool isOverlay)
{
	if (isOverlay == true) {
		GamePacket p = packetEnd(appendIntx(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"),
			((PlayerInfo*)(peer->data))->netID), text), chatColor), 1));

		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
	else
	{
		GamePacket p = packetEnd(appendIntx(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"),
			((PlayerInfo*)(peer->data))->netID), text), chatColor));

		ENetPacket* packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_peer_send(peer, 0, packet);
		delete p.data;
	}
}
void Player::OnConsoleMessage(ENetPeer* peer, string text)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), text));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::PlayAudio(ENetPeer* peer, string audioFile, int delayMS)
{
	string text = "action|play_sfx\nfile|" + audioFile + "\ndelayMS|" + to_string(delayMS) + "\n";
	BYTE* data = new BYTE[5 + text.length()];
	BYTE zero = 0;
	int type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);
	ENetPacket* packet = enet_packet_create(data,
		5 + text.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete data;
}
void Player::OnParticleEffect(ENetPeer* peer, int effect, float x, float y, int delay) {
	GamePacket p = packetEnd(appendFloat(appendIntx(appendString(createPacket(), "OnParticleEffect"), effect), x, y));
	int deathFlag = 0x19;
	memcpy(p.data + 24, &delay, 4);
	memcpy(p.data + 56, &deathFlag, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnDialogRequest(ENetPeer* peer, string args)
{
	GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), args));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnSetPos(ENetPeer* peer, int netID, int x, int y, int delay) {
	GamePacket p = packetEnd(appendFloat(appendString(createPacket(), "OnSetPos"), x, y));
	memcpy(p.data + 8, &netID, 4);
	if (delay > 0) {
		int deathFlag = 0x19;
		memcpy(p.data + 24, &delay, 4);
		memcpy(p.data + 56, &deathFlag, 4);
	}
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnAddNotification(ENetPeer* peer, string text, string audiosound, string interfaceimage)
{
	auto p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"),
		interfaceimage),
		text),
		audiosound),
		0));

	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}


void Player::OnSetBux(ENetPeer* peer, int gems, int accountstate)
{
	GamePacket p = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnSetBux"), gems), accountstate));
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
	delete p.data;
}

void Player::OnChangeSkin(ENetPeer* peer, int skinColor, int netID) {
	auto p = packetEnd(appendInt(appendString(createPacket(), "OnChangeSkin"), skinColor));
	memcpy(p.data + 8, &netID, 4);
	ENetPacket* packet = enet_packet_create(p.data,
		p.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet);
	delete p.data;
}



int getState(PlayerInfo* info) {
	int val = 0;
	val |= info->canWalkInBlocks << 0;
	val |= info->canDoubleJump << 1;
	val |= info->isInvisible << 2;
	val |= info->noHands << 3;
	val |= info->noEyes << 4;
	val |= info->noBody << 5;
	val |= info->devilHorns << 6;
	val |= info->goldenHalo << 7;
	val |= info->isFrozen << 11;
	val |= info->isCursed << 12;
	val |= info->isDuctaped << 13;
	val |= info->haveCigar << 14;
	val |= info->isShining << 15;
	val |= info->isZombie << 16;
	val |= info->isHitByLava << 17;
	val |= info->haveHauntedShadows << 18;
	val |= info->haveGeigerRadiation << 19;
	val |= info->haveReflector << 20;
	val |= info->isEgged << 21;
	val |= info->havePineappleFloag << 22;
	val |= info->haveFlyingPineapple << 23;
	val |= info->haveSuperSupporterName << 24;
	val |= info->haveSupperPineapple << 25;
	val |= info->bantape << 13;
	return val;
}


struct WorldItem {
	__int16 foreground = 0;
	__int16 background = 0;
	int breakLevel = 0;
	int yellowGems = 0;
	int blueGems = 0;
	int redGems = 0;
	int greenGems = 0;
	int purpleGems = 0;
	long long int breakTime = 0;
	bool flipped = false;
	bool activated = false;
	bool couch = false;
	bool water = false;
	bool fire = false;
	bool glue = false;
	bool red = false;
	bool green = false;
	bool blue = false;
	bool isMultifacing = false;
	string sign = "";

	bool opened = false;
};

struct DroppedItem {
	int id = 0;
	int uid = -1;
	int count = 0;
	int x = -1, y = -1;
};

struct WorldInfo {
	int width = 100;
	int height = 60;
	vector<string> accessed;
	string name = "TEST";
	vector<DroppedItem> droppedItems;
	int droppedItemUid = 0;
	bool isCasino = false;
	int droppedCount = 0;
	WorldItem* items;
	string owner = "";
	bool isPublic = false;

	//New (start}
	string ownerID = "";
	bool isJammed = false;
	bool isPunchJam = false;
	bool isZombieJam = false;
	bool isNuked = false;
	//New (End)
	unsigned long currentItemUID = 1; //has to be 1 by default
};
WorldInfo generateUnderScoreWorld(string name, int width, int height, string owner)
{
	WorldInfo world;
	world.name = name;
	world.owner = owner;
	world.isPublic = false;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width * world.height];
	for (int i = 0; i < world.width * world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 10; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 4; }
				else { world.items[i].foreground = 2; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 0; //Cave removed
		if (i == 3550)
			world.items[i].foreground = 242;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}
WorldInfo generateHELL(string name, int width, int height, string owner)
{
	WorldInfo world;
	world.name = name;
	world.owner = owner;
	world.isPublic = true;
	world.isJammed = true;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width * world.height];
	for (int i = 0; i < world.width * world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 0; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 0; }
				else { world.items[i].foreground = 0; }
			}
			else { world.items[i].foreground = 0; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 0; //Cave removed
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}
WorldInfo generateWorld(string name, int width, int height)
{
	WorldInfo world;
	world.name = name;
	world.width = width;
	world.height = height;
	world.items = new WorldItem[world.width * world.height];
	for (int i = 0; i < world.width * world.height; i++)
	{
		if (i >= 3800 && i < 5400 && !(rand() % 50)) { world.items[i].foreground = 10; }
		else if (i >= 3700 && i < 5400) {
			if (i > 5000) {
				if (i % 7 == 0) { world.items[i].foreground = 4; }
				else { world.items[i].foreground = 2; }
			}
			else { world.items[i].foreground = 2; }
		}
		else if (i >= 5400) { world.items[i].foreground = 8; }
		if (i >= 3700)
			world.items[i].background = 14;
		if (i == 3650)
			world.items[i].foreground = 6;
		else if (i >= 3600 && i < 3700)
			world.items[i].foreground = 0; //fixed the grass in the world!
		if (i == 3750)
			world.items[i].foreground = 8;
	}
	return world;
}

class PlayerDB {
public:
	static string getProperName(string name);
	static string fixColors(string text);
	static int playerLogin(ENetPeer* peer, string username, string password);
	static int playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string email, string discord);
};

string PlayerDB::getProperName(string name) {
	string newS;
	for (char c : name) newS += (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
	string ret;
	for (int i = 0; i < newS.length(); i++)
	{
		if (newS[i] == '`') i++; else ret += newS[i];
	}
	string ret2;
	for (char c : ret) if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ret2 += c;

	string username = ret2;
	if (username == "prn" || username == "con" || username == "aux" || username == "nul" || username == "com1" || username == "com2" || username == "com3" || username == "com4" || username == "com5" || username == "com6" || username == "com7" || username == "com8" || username == "com9" || username == "lpt1" || username == "lpt2" || username == "lpt3" || username == "lpt4" || username == "lpt5" || username == "lpt6" || username == "lpt7" || username == "lpt8" || username == "lpt9") {
		return "";
	}

	return ret2;
}

string PlayerDB::fixColors(string text) {
	string ret = "";
	int colorLevel = 0;
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] == '`')
		{
			ret += text[i];
			if (i + 1 < text.length())
				ret += text[i + 1];


			if (i + 1 < text.length() && text[i + 1] == '`')
			{
				colorLevel--;
			}
			else {
				colorLevel++;
			}
			i++;
		}
		else {
			ret += text[i];
		}
	}
	for (int i = 0; i < colorLevel; i++) {
		ret += "``";
	}
	for (int i = 0; i > colorLevel; i--) {
		ret += "`w";
	}
	return ret;
}
char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
'8', '9', '6', '2', '3', '1', '9', '0' };

std::string hexStr(unsigned char data)
{
	std::string s(2, ' ');
	s[0] = hexmap[(data & 0xF0) >> 4];
	s[1] = hexmap[data & 0x0F];
	return s;
}

struct Admin {
	string username;
	string password;
	int level = 0;

	long long int lastSB = 0;
};

vector<Admin> admins;

void savejson(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		std::ifstream ifff("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

		PlayerInfo* p5 = ((PlayerInfo*)(peer->data));

		string username = PlayerDB::getProperName(p5->rawName);



		if (ifff.fail()) {
			ifff.close();


		}
		if (ifff.is_open()) {
		}
		vector<string> friends;
		json j;
		ifff >> j; //load
		j["cloth_hair"] = ((PlayerInfo*)(peer->data))->cloth_hair;
		j["cloth_shirt"] = ((PlayerInfo*)(peer->data))->cloth_shirt;
		j["cloth_pants"] = ((PlayerInfo*)(peer->data))->cloth_pants;
		j["cloth_feet"] = ((PlayerInfo*)(peer->data))->cloth_feet;
		j["cloth_face"] = ((PlayerInfo*)(peer->data))->cloth_face;
		j["cloth_hand"] = ((PlayerInfo*)(peer->data))->cloth_hand;
		j["cloth_back"] = ((PlayerInfo*)(peer->data))->cloth_back;
		j["cloth_mask"] = ((PlayerInfo*)(peer->data))->cloth_mask;
		j["cloth_necklace"] = ((PlayerInfo*)(peer->data))->cloth_necklace;
		j["cloth_ances"] = ((PlayerInfo*)(peer->data))->cloth_ances;
		j["skinColor"] = ((PlayerInfo*)(peer->data))->skinColor;
		j["friends"] = friends;
		j["xp"] = ((PlayerInfo*)(peer->data))->xp;
		j["level"] = ((PlayerInfo*)(peer->data))->level;
		j["ghost"] = ((PlayerInfo*)(peer->data))->canWalkInBlocks;
		j["invis"] = ((PlayerInfo*)(peer->data))->invis;
		j["userID"] = ((PlayerInfo*)(peer->data))->userID;
		j["gem"] = ((PlayerInfo*)(peer->data))->gem;
		std::ofstream o("players/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
		if (!o.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		o << j << std::endl;
	}
}

void saveOptions(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		std::ifstream ifff("playersOptions/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
		PlayerInfo* p5 = ((PlayerInfo*)(peer->data));
		string username = PlayerDB::getProperName(p5->rawName);
		if (ifff.fail()) {
			ifff.close();
		}
		if (ifff.is_open()) {
		}
		json j;
		ifff >> j; //load
		j["BlueName"] = ((PlayerInfo*)(peer->data))->haveBluename;
		j["FastPunch"] = ((PlayerInfo*)(peer->data))->fastPunch;
		j["SuperSupporterName"] = ((PlayerInfo*)(peer->data))->haveSuperSupporterName;
		j["Cursed"] = ((PlayerInfo*)(peer->data))->isCursed;
		j["Taped"] = ((PlayerInfo*)(peer->data))->isDuctaped;
		j["Zombie"] = ((PlayerInfo*)(peer->data))->isZombie;
		j["AAP"] = ((PlayerInfo*)(peer->data))->AAP;
		j["NoteBook"] = ((PlayerInfo*)(peer->data))->personal_note;
		std::ofstream o("playersOptions/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
		if (!o.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		o << j << std::endl;
	}
}


void savePunishment(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		std::ifstream ifff("playersPunishment/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
		PlayerInfo* p5 = ((PlayerInfo*)(peer->data));
		string username = PlayerDB::getProperName(p5->rawName);
		if (ifff.fail()) {
			ifff.close();


		}
		if (ifff.is_open()) {
		}
		json j;
		ifff >> j; //load
		j["isBanned"] = ((PlayerInfo*)(peer->data))->banned;
		j["isCursed"] = ((PlayerInfo*)(peer->data))->cursed;
		j["isMuted"] = ((PlayerInfo*)(peer->data))->taped;
		j["isFrozen"] = ((PlayerInfo*)(peer->data))->isFrozen;
		j["IP"] = ((PlayerInfo*)(peer->data))->charIP;
		std::ofstream o("playersPunishment/" + ((PlayerInfo*)(peer->data))->rawName + ".json"); //save
		if (!o.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		o << j << std::endl;
	}
}

void UpdatePlayer(ENetPeer* peer) {
	std::ifstream ifs("playersPunishment/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->rawName) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		bool ban = j["isBanned"];
		bool crd = j["isCursed"];
		bool tpd = j["isMuted"];
		bool frz = j["isFrozen"];
		((PlayerInfo*)(peer->data))->banned = ban;
		((PlayerInfo*)(peer->data))->cursed = crd;
		((PlayerInfo*)(peer->data))->taped = tpd;
		((PlayerInfo*)(peer->data))->isFrozen = frz;
	}
	std::ifstream ifss("playersOptions/" + PlayerDB::getProperName(((PlayerInfo*)(peer->data))->rawName) + ".json");
	if (ifss.is_open()) {
		json j;
		ifss >> j;
		bool bn = j["BlueName"];
		bool fp = j["FastPunch"];
		bool ssn = j["SuperSupporterName"];
		bool cd = j["Cursed"];
		bool td = j["Taped"];
		bool ze = j["Zombie"];
		string note = j["NoteBook"];
		string AAP = j["AAP"];
		((PlayerInfo*)(peer->data))->haveBluename = bn;
		((PlayerInfo*)(peer->data))->fastPunch = fp;
		((PlayerInfo*)(peer->data))->haveSuperSupporterName = ssn;
		((PlayerInfo*)(peer->data))->isCursed = cd;
		((PlayerInfo*)(peer->data))->isDuctaped = td;
		((PlayerInfo*)(peer->data))->isZombie = ze;
		((PlayerInfo*)(peer->data))->AAP = AAP;
		((PlayerInfo*)(peer->data))->personal_note = note;
	}
}

int PlayerDB::playerLogin(ENetPeer* peer, string username, string password) {
	std::ifstream ifs("players/" + PlayerDB::getProperName(username) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		string pss = j["password"];
		string userid = j["userID"];
		int adminLevel = j["adminLevel"];
		int skinColor = j["skinColor"];
		if (verifyPassword(password, pss)) {
			((PlayerInfo*)(peer->data))->hasLogon = true;
			((PlayerInfo*)(peer->data))->adminLevel = adminLevel;
			((PlayerInfo*)(peer->data))->skinColor = skinColor;
			((PlayerInfo*)(peer->data))->cloth_hair = j["cloth_hair"];
			((PlayerInfo*)(peer->data))->cloth_shirt = j["cloth_shirt"];
			((PlayerInfo*)(peer->data))->cloth_pants = j["cloth_pants"];
			((PlayerInfo*)(peer->data))->cloth_ances = j["cloth_ances"];
			((PlayerInfo*)(peer->data))->cloth_necklace = j["cloth_necklace"];
			((PlayerInfo*)(peer->data))->cloth_mask = j["cloth_mask"];
			((PlayerInfo*)(peer->data))->cloth_face = j["cloth_face"];
			((PlayerInfo*)(peer->data))->cloth_feet = j["cloth_feet"];
			((PlayerInfo*)(peer->data))->cloth_back = j["cloth_back"];
			((PlayerInfo*)(peer->data))->cloth_hand = j["cloth_hand"];
			((PlayerInfo*)(peer->data))->level = j["level"];
			((PlayerInfo*)(peer->data))->xp = j["xp"];
			((PlayerInfo*)(peer->data))->gem = j["gem"];
			((PlayerInfo*)(peer->data))->canWalkInBlocks = j["ghost"];
			((PlayerInfo*)(peer->data))->invis = j["invis"]; // do like this
			if (j["userID"] == "") {
				string x;
				for (int i = 0; i < 3; i++)
				{
					x += hexStr(rand());
				}
				for (auto& c : x) c = toupper(c);
				((PlayerInfo*)(peer->data))->userID = x;
				savejson(peer);
				enet_peer_disconnect_later(peer, 0);//
			}
			else {
				((PlayerInfo*)(peer->data))->userID = userid;
			}
			//+
			std::ifstream ifs("playersPunishment/" + PlayerDB::getProperName(username) + ".json");
			if (ifs.is_open()) {
				json j;
				ifs >> j;
				bool ban = j["isBanned"];
				bool crd = j["isCursed"];
				bool tpd = j["isMuted"];
				bool frz = j["isFrozen"];
				((PlayerInfo*)(peer->data))->banned = ban;
				((PlayerInfo*)(peer->data))->cursed = crd;
				((PlayerInfo*)(peer->data))->taped = tpd;
				((PlayerInfo*)(peer->data))->isFrozen = frz;

			}
				std::ofstream o("playersPunishment/" + PlayerDB::getProperName(username) + ".json");
				{
					if (!o.is_open()) {
						cout << GetLastError() << endl;
						_getch();
					}
					json j;
					j["isBanned"] = false;
					j["isCursed"] = false;
					j["isMuted"] = false;
					j["isFrozen"] = false;
					j["IP"] = ((PlayerInfo*)(peer->data))->charIP;
					o << j << std::endl;
				}
			//
			std::ifstream ifss("playersOptions/" + PlayerDB::getProperName(username) + ".json");
			if (ifss.is_open()) {
				json j;
				ifss >> j;
				bool bn = j["BlueName"];
				bool fp = j["FastPunch"];
				bool ssn = j["SuperSupporterName"];
				bool cd = j["Cursed"];
				bool td = j["Taped"];
				bool ze = j["Zombie"];
				string note = j["NoteBook"];
				string AAP = j["AAP"];
				((PlayerInfo*)(peer->data))->haveBluename = bn;
				((PlayerInfo*)(peer->data))->fastPunch = fp;
				((PlayerInfo*)(peer->data))->haveSuperSupporterName = ssn;
				((PlayerInfo*)(peer->data))->isCursed = cd;
				((PlayerInfo*)(peer->data))->isDuctaped = td;
				((PlayerInfo*)(peer->data))->isZombie = ze;
				((PlayerInfo*)(peer->data))->AAP = AAP;
				((PlayerInfo*)(peer->data))->personal_note = note;
			}
			else {
				std::ofstream o("playersOptions/" + PlayerDB::getProperName(username) + ".json");
				{
					if (!o.is_open()) {
						cout << GetLastError() << endl;
						_getch();
					}
					json j;
					j["BlueName"] = false;
					j["FastPunch"] = false;
					j["SuperSupporterName"] = false;
					j["Cursed"] = false;
					j["Taped"] = false;
					j["Zombie"] = false;
					j["AAP"] = "";
					j["NoteBook"] = "";
					o << j << std::endl;
				}
			}
			// 
			//after verify password add adminlevel not before
			bool found = false;
			for (int i = 0; i < admins.size(); i++) {
				if (admins[i].username == username) {
					found = true;
				}
			}
			if (!found) {//not in vector
				if (adminLevel != 0) {
					Admin admin;
					admin.username = PlayerDB::getProperName(username);
					admin.password = pss;
					admin.level = adminLevel;
					admins.push_back(admin);
				}
			}
			ENetPeer* currentPeer;

			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (currentPeer == peer)
					continue;
				if (((PlayerInfo*)(currentPeer->data))->rawName == PlayerDB::getProperName(username))
				{
					{
						gamepacket_t p;
						p.Insert("OnConsoleMessage");
						p.Insert("`4WARNING`o : `oSomeone else logged into this account!");
						p.CreatePacket(peer);

					}
					{
						gamepacket_t p;
						p.Insert("OnConsoleMessage");
						p.Insert("`4ALREADY ON?!`o : This account was already online, kicking it off so you can log on. (if you were just playing before, this is nothing to worry about)");
						p.CreatePacket(peer);
					}
					enet_peer_disconnect_later(currentPeer, 0);
				}
			}
			return 1;
		}
		else {
			return -1;
		}
	}
	else {
		return -2;
	}
}

int PlayerDB::playerRegister(ENetPeer* peer, string username, string password, string passwordverify, string email, string discord) {
	string name = username;
	if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") return -1;
	username = PlayerDB::getProperName(username);
	if (discord.find("#") == std::string::npos && discord.length() != 0) return -5;
	if (email.find("@") == std::string::npos && email.length() != 0) return -4;
	if (passwordverify != password) return -3;
	if (username.length() < 3) return -2;
	std::ifstream ifs("players/" + username + ".json");
	if (ifs.is_open()) {
		return -1;
	}
	ENetPeer* currentPeer;
	currentPeer = server->peers;
	std::ofstream o("players/" + username + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	vector<string> friends;
	json j;
	j["username"] = username;
	j["password"] = hashPassword(password);
	j["cloth_hair"] = ((PlayerInfo*)(peer->data))->cloth_hair;
	j["cloth_shirt"] = ((PlayerInfo*)(peer->data))->cloth_shirt;
	j["cloth_pants"] = ((PlayerInfo*)(peer->data))->cloth_pants;
	j["cloth_feet"] = ((PlayerInfo*)(peer->data))->cloth_feet;
	j["cloth_face"] = ((PlayerInfo*)(peer->data))->cloth_face;
	j["cloth_hand"] = ((PlayerInfo*)(peer->data))->cloth_hand;
	j["cloth_back"] = ((PlayerInfo*)(peer->data))->cloth_back;
	j["cloth_mask"] = ((PlayerInfo*)(peer->data))->cloth_mask;
	j["cloth_necklace"] = ((PlayerInfo*)(peer->data))->cloth_necklace;
	j["cloth_ances"] = ((PlayerInfo*)(peer->data))->cloth_ances;
	j["friends"] = friends;
	j["level"] = 1;
	j["xp"] = 0;
	j["invis"] = ((PlayerInfo*)(peer->data))->invis;
	j["skinColor"] = ((PlayerInfo*)(peer->data))->skinColor;
	j["ghost"] = ((PlayerInfo*)(peer->data))->canWalkInBlocks;
	j["email"] = email;
	j["discord"] = discord;
	j["adminLevel"] = 0;
	j["gem"] = ((PlayerInfo*)(peer->data))->gem;
	j["userID"] = "";
	o << j << std::endl;
	return 1;
}

struct AWorld {
	WorldInfo* ptr;
	WorldInfo info;
	int id;
};

class WorldDB {
public:
	WorldInfo get(ENetPeer* peer, string name);
	AWorld get2(ENetPeer* peer, string name);
	void flush(WorldInfo info);
	void flush2(AWorld info);
	void save(AWorld info);
	void saveAll();
	void saveRedundant();
	void saveWorld(ENetPeer* peer, string name);
	vector<WorldInfo> getRandomWorlds();
	WorldDB();
private:
	vector<WorldInfo> worlds;
};

WorldDB::WorldDB() {
	// Constructor
}

namespace packet {
	void consolemessage(ENetPeer* peer, string message) {
		gamepacket_t p;
		p.Insert("OnConsoleMessage");
		p.Insert(message);
		p.CreatePacket(peer);
	}
	void dialog(ENetPeer* peer, string message) {
		gamepacket_t p;
		p.Insert("OnDialogRequest");
		p.Insert(message);
		p.CreatePacket(peer);
	}
	void onspawn(ENetPeer* peer, string message) {
		gamepacket_t p;
		p.Insert("OnSpawn");
		p.Insert(message);
		p.CreatePacket(peer);
	}
	void requestworldselectmenu(ENetPeer* peer, string message) {
		gamepacket_t p;
		p.Insert("OnRequestWorldSelectMenu");
		p.Insert(message);
		p.CreatePacket(peer);
	}
	void storerequest(ENetPeer* peer, string message) {
		gamepacket_t p;
		p.Insert("OnStoreRequest");
		p.Insert(message);
		p.CreatePacket(peer);
	}
	void storepurchaseresult(ENetPeer* peer, string message) {
		gamepacket_t p;
		p.Insert("OnStorePurchaseResult");
		p.Insert(message);
		p.CreatePacket(peer);
	}
}

string getStrUpper(string txt) {
	string ret;
	for (char c : txt) ret += toupper(c);
	return ret;
}

AWorld WorldDB::get2(ENetPeer* peer, string name) {
	if (worlds.size() > 200) {
#ifdef TOTAL_LOG
		cout << "Saving redundant worlds!" << endl;
#endif
		saveRedundant();
#ifdef TOTAL_LOG
		cout << "Redundant worlds are saved!" << endl;
#endif
	}

	AWorld ret;
	name = getStrUpper(name);
	if (name.length() < 1) throw 1; // too short name
	for (char c : name) {
		if (((PlayerInfo*)(peer->data))->adminLevel == 5 || ((PlayerInfo*)(peer->data))->haveGrowId == false || ((PlayerInfo*)(peer->data))->bypass_underscore == true || name == "BETA_TESTING") {
			if ((c < 'A' || c>'Z') && (c < '0' || c>'9') && (c < '_' || c>'_'))
				throw 2; // wrong name
		}
		else {
			if ((c < 'A' || c>'Z') && (c < '0' || c>'9'))
				throw 2; // wrong name
		}
	}
	if (name == "BETA") {
		((PlayerInfo*)(peer->data))->sendToWorld = "BETA_TESTING";
	}
	/*if (cursed = true) {
		((PlayerInfo*)(peer->data))->sendToWorld = "HELL";
	}*/
	if (name == "EXIT") {
		throw 3;
	}
	//if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "COM1" || name == "COM2" || name == "COM3" || name == "COM4" || name == "COM5" || name == "COM6" || name == "COM7" || name == "COM8" || name == "COM9" || name == "LPT1" || name == "LPT2" || name == "LPT3" || name == "LPT4" || name == "LPT5" || name == "LPT6" || name == "LPT7" || name == "LPT8" || name == "LPT9") throw 3;
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			ret.id = i;
			ret.info = worlds.at(i);
			ret.ptr = &worlds.at(i);
			return ret;
		}

	}
	std::ifstream ifs("worlds/_" + name + ".json");
	if (ifs.is_open()) {

		json j;
		ifs >> j;
		WorldInfo info;
		info.name = j["name"].get<string>();
		info.width = j["width"];
		info.height = j["height"];
		info.owner = j["owner"].get<string>();
		info.ownerID = j["ownerID"].get<string>();
		info.isJammed = j["isJammed"].get<bool>();
		info.isPunchJam = j["isPunchJam"].get<bool>();
		info.isZombieJam = j["isZombieJam"].get<bool>();
		info.isNuked = j["isNuked"].get<bool>();
		info.isPublic = j["isPublic"];
		json tiles = j["tiles"];
		json droppedobjects = j["dropped"];
		for (int i = 0; i < droppedobjects.size(); i++) {
			DroppedItem di;
			di.count = droppedobjects[i]["c"].get<byte>();
			di.id = droppedobjects[i]["id"].get<short>();
			di.x = droppedobjects[i]["x"].get<int>();
			di.y = droppedobjects[i]["y"].get<int>();
			di.uid = droppedobjects[i]["uid"].get<int>();
			info.droppedItems.push_back(di);
		}
		int square = info.width * info.height;
		info.items = new WorldItem[square];
		for (int i = 0; i < square; i++) {
			info.items[i].foreground = tiles[i]["fg"];
			info.items[i].background = tiles[i]["bg"];
			info.items[i].sign = tiles[i]["sign"].get<string>();
			info.items[i].activated = tiles[i]["actv"].get<bool>();
			info.items[i].isMultifacing = tiles[i]["mltv"].get<bool>();
			info.items[i].opened = tiles[i]["open"].get<bool>();
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	else {
		WorldInfo info;
		if (name.find("_") != string::npos && ((PlayerInfo*)(peer->data))->adminLevel == 5) {
			info = generateUnderScoreWorld(name, 100, 60, ((PlayerInfo*)(peer->data))->rawName);
		}
		else if (name == "HELL") {
			info = generateHELL(name, 100, 60, ((PlayerInfo*)(peer->data))->rawName);
		}
		else {
			info = generateWorld(name, 100, 60);
		}
		worlds.push_back(info);
		ret.id = worlds.size() - 1;
		ret.info = info;
		ret.ptr = &worlds.at(worlds.size() - 1);
		return ret;
	}
	throw 1;
}

WorldInfo WorldDB::get(ENetPeer* peer, string name) {

	return this->get2(peer, name).info;
}

void WorldDB::flush(WorldInfo info)
{
	std::ofstream o("worlds/_" + info.name + ".json");
	if (!o.is_open()) {
		cout << GetLastError() << endl;
	}
	json j;
	j["name"] = info.name;
	j["width"] = info.width;
	j["height"] = info.height;
	j["owner"] = info.owner;
	j["ownerID"] = info.ownerID;
	j["isPublic"] = info.isPublic;
	j["isJammed"] = info.isJammed;
	j["isPunchJam"] = info.isPunchJam;
	j["isZombieJam"] = info.isZombieJam;
	j["isNuked"] = info.isNuked;
	json tiles = json::array();
	int square = info.width * info.height;
	json droppedarr = json::array();
	for (int i = 0; i < info.droppedItems.size(); i++)
	{
		json droppedJ;
		droppedJ["c"] = (byte)info.droppedItems[i].count;
		droppedJ["id"] = (short)info.droppedItems[i].id;
		droppedJ["x"] = info.droppedItems[i].x;
		droppedJ["y"] = info.droppedItems[i].y;
		droppedJ["uid"] = info.droppedItems[i].uid;
		droppedarr.push_back(droppedJ);
	}
	for (int i = 0; i < square; i++)
	{
		json tile;
		tile["fg"] = info.items[i].foreground;
		tile["bg"] = info.items[i].background;
		tile["sign"] = info.items[i].sign;
		tile["actv"] = info.items[i].activated;
		tile["mltv"] = info.items[i].isMultifacing;
		tile["open"] = info.items[i].opened;
		tiles.push_back(tile);
	}
	j["dropped"] = droppedarr; // here
	j["tiles"] = tiles;
	o << j << std::endl;
}

void WorldDB::flush2(AWorld info)
{

	this->flush(info.info);
	//cout << "Saved worlds: "+ to_string(saved) +", unsaved worlds: " +to_string(notsaved) << endl;
}

void WorldDB::save(AWorld info)
{
	flush2(info);
	delete info.info.items;
	worlds.erase(worlds.begin() + info.id);
}

void WorldDB::saveWorld(ENetPeer* peer, string name) {
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).name == name)
		{
			flush(worlds.at(i));
		}
	}
}
void WorldDB::saveAll()
{
	int saved = 0, notsaved = 0;
	for (int i = 0; i < worlds.size(); i++) {
		if (worlds.at(i).owner != "") {
			flush(worlds.at(i));
			delete[] worlds.at(i).items;
			saved += 1;
		}
		if (worlds.at(i).owner == "") {
			notsaved += 1;
		}
	}
	worlds.clear();
	cout << "Saved worlds: " + to_string(saved) + ", unsaved worlds: " + to_string(notsaved) << endl;
	cout << "[LAG REDUCE]" << endl;
}

vector<WorldInfo> WorldDB::getRandomWorlds() {
	vector<WorldInfo> ret;
	for (int i = 0; i < ((worlds.size() < 10) ? worlds.size() : 10); i++)
	{ // load first four worlds, it is excepted that they are special
		ret.push_back(worlds.at(i));
	}
	// and lets get up to 6 random
	if (worlds.size() > 4) {
		for (int j = 0; j < 6; j++)
		{
			bool isPossible = true;
			WorldInfo world = worlds.at(rand() % (worlds.size() - 4));
			for (int i = 0; i < ret.size(); i++)
			{
				if (world.name == ret.at(i).name || world.name == "EXIT")
				{
					isPossible = false;
				}
			}
			if (isPossible)
				ret.push_back(world);
		}
	}
	return ret;
}

void WorldDB::saveRedundant()
{
	for (int i = 4; i < worlds.size(); i++) {
		bool canBeFree = true;
		ENetPeer* currentPeer;

		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (((PlayerInfo*)(currentPeer->data))->currentWorld == worlds.at(i).name)
				canBeFree = false;
		}
		if (canBeFree)
		{
			flush(worlds.at(i));
			delete worlds.at(i).items;
			worlds.erase(worlds.begin() + i);
			i--;
		}
	}
}

//WorldInfo world;
//vector<WorldInfo> worlds;
WorldDB worldDB;
void saveCurrentWorld(ENetPeer* peers, string name) // atexit hack plz fix
{
	saveTotal += 1;
	cout << "[save system works about " + to_string(saveTotal) + " times]\n[Saving World Name: " + name + "]\n";
	worldDB.saveWorld(peers, name);
}


void saveAllWorlds() // atexit hack plz fix
{
	cout << "Saving worlds..." << endl;
	worldDB.saveAll();
	cout << "Worlds saved!" << endl;
}

WorldInfo* getPlyersWorld(ENetPeer* peer)
{
	try {
		return worldDB.get2(peer, ((PlayerInfo*)(peer->data))->currentWorld).ptr;
	}
	catch (int e) {
		return NULL;
	}
}



enum ClothTypes {
	HAIR,
	SHIRT,
	PANTS,
	FEET,
	FACE,
	HAND,
	BACK,
	MASK,
	NECKLACE,
	ANCES,
	NONE
};

enum BlockTypes {
	FOREGROUND,
	BACKGROUND,
	CONSUMABLE,
	SEED,
	CHECKPOINT,
	WRENCH,
	LOCK,
	GATEWAY,
	PLATFORM,
	SWITCH_BLOCK,
	TRAMPOLINE,
	TOGGLE_FOREGROUND,
	ANIM_FOREGROUND,
	BOUNCY,
	BULLETIN_BOARD,
	CHEST,
	COMPONENT,
	DEADLY,
	FACTION,
	GEMS,
	MAGIC_EGG,
	PORTAL,
	RANDOM_BLOCK,
	SFX_FOREGROUND,
	TREASURE,
	PAIN_BLOCK,
	BEDROCK,
	MAIN_DOOR,
	SIGN,
	DOOR,
	CLOTHING,
	MAILBOX,
	FIST,
	UNKNOWN
};

#define Property_Zero 0
#define Property_NoSeed 1
#define Property_Dropless 2
#define Property_Beta 4
#define Property_Mod 8
#define Property_Chemical 12
#define Property_Untradable 16
#define Property_Wrenchable 32
#define Property_MultiFacing 64
#define Property_Permanent 128
#define Property_AutoPickup 256
#define Property_WorldLock 512
#define Property_NoSelf 1024
#define Property_RandomGrow 2048
#define Property_Public 4096
#define Property_Foreground 8192

struct ItemDefinition {
	int id;

	unsigned char editableType = 0;
	unsigned char itemCategory = 0;
	unsigned char actionType = 0;
	unsigned char hitSoundType = 0;

	string name;

	string texture = "";
	int textureHash = 0;
	unsigned char itemKind = 0;
	int val1;
	unsigned char textureX = 0;
	unsigned char textureY = 0;
	unsigned char spreadType = 0;
	unsigned char isStripeyWallpaper = 0;
	unsigned char collisionType = 0;

	unsigned char breakHits = 0;

	int dropChance = 0;
	unsigned char clothingType = 0;
	BlockTypes blockType;
	int growTime;
	ClothTypes clothType;
	int rarity;
	unsigned char maxAmount = 0;
	string extraFile = "";
	int extraFileHash = 0;
	int audioVolume = 0;
	string petName = "";
	string petPrefix = "";
	string petSuffix = "";
	string petAbility = "";
	unsigned	char seedBase = 0;
	unsigned	char seedOverlay = 0;
	unsigned	char treeBase = 0;
	unsigned	char treeLeaves = 0;
	int seedColor = 0;
	int seedOverlayColor = 0;
	bool isMultiFace = false;
	short val2;
	short isRayman = 0;
	string extraOptions = "";
	string texture2 = "";
	string extraOptions2 = "";
	string punchOptions = "";
	int properties;
	string description = "Nothing to see.";
};

vector<ItemDefinition> itemDefs;

ItemDefinition getItemDef(int id)
{
	if (id < itemDefs.size() && id > -1)
		return itemDefs.at(id);
	/*for (int i = 0; i < itemDefs.size(); i++)
	{
		if (id == itemDefs.at(i).id)
		{
			return itemDefs.at(i);
		}
	}*/
	throw 0;
	return itemDefs.at(0);
}

void craftItemDescriptions() {
	int current = -1;
	std::ifstream infile("Descriptions.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 3 && line[0] != '/' && line[1] != '/')
		{
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			if (atoi(ex[0].c_str()) + 1 < itemDefs.size())
			{
				itemDefs.at(atoi(ex[0].c_str())).description = ex[1];
				if (!(atoi(ex[0].c_str()) % 2))
					itemDefs.at(atoi(ex[0].c_str()) + 1).description = "This is a tree.";
			}
		}
	}
}

std::ifstream::pos_type filesize(const char* filename)
{
	std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
	return in.tellg();
}

uint32_t HashString(unsigned char* str, int len)
{
	if (!str) return 0;

	unsigned char* n = (unsigned char*)str;
	uint32_t acc = 0x55555555;

	if (len == 0)
	{
		while (*n)
			acc = (acc >> 27) + (acc << 5) + *n++;
	}
	else
	{
		for (int i = 0; i < len; i++)
		{
			acc = (acc >> 27) + (acc << 5) + *n++;
		}
	}
	return acc;

}

unsigned char* getA(string fileName, int* pSizeOut, bool bAddBasePath, bool bAutoDecompress)
{
	unsigned char* pData = NULL;
	FILE* fp = fopen(fileName.c_str(), "rb");
	if (!fp)
	{
		cout << "File not found" << endl;
		if (!fp) return NULL;
	}

	fseek(fp, 0, SEEK_END);
	*pSizeOut = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	pData = (unsigned char*)new unsigned char[((*pSizeOut) + 1)];
	if (!pData)
	{
		printf("Out of memory opening %s?", fileName.c_str());
		return 0;
	}
	pData[*pSizeOut] = 0;
	fread(pData, *pSizeOut, 1, fp);
	fclose(fp);

	return pData;
}

int itemdathash;
int coredatasize;
void buildItemsDatabase()
{
	std::ifstream file("items.dat", std::ios::binary | std::ios::ate);
	itemsDatSize = file.tellg();
	itemsDat = new BYTE[60 + itemsDatSize];
	string asdf = "0400000010000000FFFFFFFF000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(itemsDat + (i / 2), &x, 1);
		if (asdf.length() > 60 * 2) throw 0;
	}
	memcpy(itemsDat + 56, &itemsDatSize, 4);
	file.seekg(0, std::ios::beg);

	if (file.read((char*)(itemsDat + 60), itemsDatSize))
	{
		uint8_t* pData;
		int size = 0;
		const char filename[] = "items.dat";
		size = filesize(filename);
		pData = getA((string)filename, &size, false, false);
		cout << "Updating items data success! Hash: " << HashString((unsigned char*)pData, size) << endl;
		itemdathash = HashString((unsigned char*)pData, size);
		file.close();

	}
	else {
		cout << "Updating items data failed! (no items.dat file found!)" << endl;
	}
	int current = -1;
	std::ifstream infile("CoreData.txt");
	for (std::string line; getline(infile, line);)
	{
		if (line.length() > 8 && line[0] != '/' && line[1] != '/')
		{
			coredatasize++;
			vector<string> ex = explode("|", line);
			ItemDefinition def;
			def.id = atoi(ex[0].c_str());
			def.name = ex[1];
			def.rarity = atoi(ex[2].c_str());
			vector<string> properties = explode(",", ex[3]);
			def.properties = Property_Zero;
			for (auto& prop : properties)
			{
				if (prop == "NoSeed")
					def.properties |= Property_NoSeed;
				if (prop == "Dropless")
					def.properties |= Property_Dropless;
				if (prop == "Beta")
					def.properties |= Property_Beta;
				if (prop == "Mod")
					def.properties |= Property_Mod;
				if (prop == "Untradable")
					def.properties |= Property_Untradable;
				if (prop == "Wrenchable")
					def.properties |= Property_Wrenchable;
				if (prop == "MultiFacing")
					def.properties |= Property_MultiFacing;
				if (prop == "Permanent")
					def.properties |= Property_Permanent;
				if (prop == "AutoPickup")
					def.properties |= Property_AutoPickup;
				if (prop == "WorldLock")
					def.properties |= Property_WorldLock;
				if (prop == "NoSelf")
					def.properties |= Property_NoSelf;
				if (prop == "RandomGrow")
					def.properties |= Property_RandomGrow;
				if (prop == "Public")
					def.properties |= Property_Public;
			}
			string bt = ex[4];
			if (bt == "Foreground_Block") {
				def.blockType = BlockTypes::FOREGROUND;
			}
			else if (bt == "Seed") {
				def.blockType = BlockTypes::SEED;
			}
			else if (bt == "Consummable") {
				def.blockType = BlockTypes::CONSUMABLE;
			}
			else if (bt == "Pain_Block") {
				def.blockType = BlockTypes::PAIN_BLOCK;
			}
			else if (bt == "Main_Door") {
				def.blockType = BlockTypes::MAIN_DOOR;
			}
			else if (bt == "Bedrock") {
				def.blockType = BlockTypes::BEDROCK;
			}
			else if (bt == "Door") {
				def.blockType = BlockTypes::DOOR;
			}
			else if (bt == "Fist") {
				def.blockType = BlockTypes::FIST;
			}
			else if (bt == "Sign") {
				def.blockType = BlockTypes::SIGN;
			}
			else if (bt == "Background_Block") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else if (bt == "Sheet_Music") {
				def.blockType = BlockTypes::BACKGROUND;
			}
			else if (bt == "Wrench") {
				def.blockType = BlockTypes::WRENCH;
			}
			else if (bt == "Checkpoint") {
				def.blockType = BlockTypes::CHECKPOINT;
			}
			else if (bt == "Lock") {
				def.blockType = BlockTypes::LOCK;
			}
			else if (bt == "Gateway") {
				def.blockType = BlockTypes::GATEWAY;
			}
			else if (bt == "Clothing") {
				def.blockType = BlockTypes::CLOTHING;
			}
			else if (bt == "Platform") {
				def.blockType = BlockTypes::PLATFORM;
			}
			else if (bt == "SFX_Foreground") {
				def.blockType = BlockTypes::SFX_FOREGROUND;
			}
			else if (bt == "Gems") {
				def.blockType = BlockTypes::GEMS;
			}
			else if (bt == "Toggleable_Foreground") {
				def.blockType = BlockTypes::TOGGLE_FOREGROUND;
			}
			else if (bt == "Treasure") {
				def.blockType = BlockTypes::TREASURE;
			}
			else if (bt == "Deadly_Block") {
				def.blockType = BlockTypes::DEADLY;
			}
			else if (bt == "Trampoline_Block") {
				def.blockType = BlockTypes::TRAMPOLINE;
			}
			else if (bt == "Animated_Foreground_Block") {
				def.blockType = BlockTypes::ANIM_FOREGROUND;
			}
			else if (bt == "Portal") {
				def.blockType = BlockTypes::PORTAL;
			}
			else if (bt == "Random_Block") {
				def.blockType = BlockTypes::RANDOM_BLOCK;
			}
			else if (bt == "Bouncy") {
				def.blockType = BlockTypes::BOUNCY;
			}
			else if (bt == "Chest") {
				def.blockType = BlockTypes::CHEST;
			}
			else if (bt == "Switch_Block") {
				def.blockType = BlockTypes::SWITCH_BLOCK;
			}
			else if (bt == "Magic_Egg") {
				def.blockType = BlockTypes::MAGIC_EGG;
			}
			else if (bt == "Mailbox") {
				def.blockType = BlockTypes::MAILBOX;
			}
			else if (bt == "Bulletin_Board") {
				def.blockType = BlockTypes::BULLETIN_BOARD;
			}
			else if (bt == "Faction") {
				def.blockType = BlockTypes::FACTION;
			}
			else if (bt == "Component") {
				def.blockType = BlockTypes::COMPONENT;
			}
			else {
				//cout << "Unknown property for ID: " << def.id << " which wants property " << bt << endl;
				def.blockType = BlockTypes::UNKNOWN;
			}
			def.breakHits = atoi(ex[7].c_str());
			def.growTime = atoi(ex[8].c_str());
			string cl = ex[9];
			if (def.blockType == BlockTypes::CLOTHING)
			{
				if (cl == "None") {
					def.clothType = ClothTypes::NONE;
				}
				else if (cl == "Hat") {
					def.clothType = ClothTypes::HAIR;
				}
				else if (cl == "Shirt") {
					def.clothType = ClothTypes::SHIRT;
				}
				else if (cl == "Pants") {
					def.clothType = ClothTypes::PANTS;
				}
				else if (cl == "Feet") {
					def.clothType = ClothTypes::FEET;
				}
				else if (cl == "Face") {
					def.clothType = ClothTypes::FACE;
				}
				else if (cl == "Hand") {
					def.clothType = ClothTypes::HAND;
				}
				else if (cl == "Back") {
					def.clothType = ClothTypes::BACK;
				}
				else if (cl == "Hair") {
					def.clothType = ClothTypes::MASK;
				}
				else if (cl == "Chest") {
					def.clothType = ClothTypes::NECKLACE;
				}
				else {
					def.clothType = ClothTypes::NONE;
				}
			}
			else
			{
				def.clothType = ClothTypes::NONE;
			}

			if (++current != def.id)
			{
				cout << "Critical error! Unordered database at item " << std::to_string(current) << "/" << std::to_string(def.id) << "!" << endl;
			}

			itemDefs.push_back(def);
		}
	}
	craftItemDescriptions();
}

void addAdmin(string username, string password, int level)
{
	Admin admin;
	admin.username = username;
	admin.password = password;
	admin.level = level;
	admins.push_back(admin);
}

string getAdminPrefix(string name, bool nameOnBlock) {
	int admin = 0; string myname = "";
	std::ifstream ifs("players/" + PlayerDB::getProperName(name) + ".json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		myname = j["username"].get<string>();
		admin = j["adminLevel"].get<int>();
	}
	else {
		myname = "Deleted-User"; admin = 0;
	}
	string x;
	if (admin == 5) {
		x = "`6@" + myname;
	}
	else if (admin == 4) {//co
		x = "`e@" + myname;
	}
	else if (admin == 3) {//admin
		x = "`4@" + myname;
	}
	else if (admin == 2) {//mod
		x = "`#@" + myname;
	}
	else if (admin == 1) {//vip
		x = "`3@" + myname;
	}
	else {
		if (nameOnBlock == false) {
			x = "`o" + myname;
		}
		else {
			x = "`w" + myname;
		}
	}
	return x;
}
int getAdminLevel(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level;
		}
	}
	return 0;
}

bool canSB(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 1) {
			using namespace std::chrono;
			if (admin.lastSB + 900000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count() || admin.level == 999)
			{
				admins[i].lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
				return true;
			}
			else {
				return false;
			}
		}
	}
	return false;
}

bool canClear(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password) {
			return admin.level > 0;
		}
	}
	return false;
}
bool isMod(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level > 2) {
			return true;
		}
	}
	return false;
}
bool isSuperAdmin(string username, string password) {
	for (int i = 0; i < admins.size(); i++) {
		Admin admin = admins[i];
		if (admin.username == username && admin.password == password && admin.level == 5) {
			return true;
		}
	}
	return false;
}

void SendRegisterDialog(ENetPeer* peer)
{
	string dialog = "text_scaling_string|Dirttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt|\nset_default_color|`o\n\nadd_label_with_icon|big|`wGet a GrowID``|left|206|\n\nadd_spacer|small|\nadd_textbox|A `wGrowID `wmeans `oyou can use a name and password to logon from any device.|\nadd_spacer|small|\nadd_textbox|This `wname `owill be reserved for you and `wshown to other players`o, so choose carefully!|\nadd_text_input|username|GrowID||30|\nadd_text_input|password|Password||100|\nadd_text_input|passwordverify|Password Verify||100|\nadd_textbox|Your `wemail address `owill only be used for account verification purposes and won't be spammed or shared. If you use a fake email, you'll never be able to recover or change your password.|\nadd_text_input|email|Email||100|\nadd_textbox|Your `wDiscord ID `owill be used for secondary verification if you lost access to your `wemail address`o! Please enter in such format: `wdiscordname#tag`o. Your `wDiscord Tag `ocan be found in your `wDiscord account settings`o.|\nadd_text_input|discord|Discord||100|\nend_dialog|register|Cancel|Get My GrowID!|\n";
	GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), dialog));
	int respawnTimeout = 500;
	int deathFlag = 0x19;
	memcpy(p2.data + 24, &respawnTimeout, 4);
	memcpy(p2.data + 56, &deathFlag, 4);
	ENetPacket* packet2 = enet_packet_create(p2.data,
		p2.len,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet2);
}

void sendInventory(ENetPeer* peer, PlayerInventory inventory)
{
	string asdf2 = "0400000009A7379237BB2509E8E0EC04F8720B050000000000000000FBBB0000010000007D920100FDFDFDFD04000000040000000000000000000000000000000000";
	int inventoryLen = inventory.items.size();
	int packetLen = (asdf2.length() / 2) + (inventoryLen * 4) + 4;
	BYTE* data2 = new BYTE[packetLen];
	for (int i = 0; i < asdf2.length(); i += 2)
	{
		char x = ch2n(asdf2[i]);
		x = x << 4;
		x += ch2n(asdf2[i + 1]);
		memcpy(data2 + (i / 2), &x, 1);
	}
	int endianInvVal = _byteswap_ulong(inventoryLen);
	memcpy(data2 + (asdf2.length() / 2) - 4, &endianInvVal, 4);
	endianInvVal = _byteswap_ulong(inventory.inventorySize);
	memcpy(data2 + (asdf2.length() / 2) - 8, &endianInvVal, 4);
	int val = 0;
	for (int i = 0; i < inventoryLen; i++)
	{
		val = 0;
		val |= inventory.items.at(i).itemID;
		val |= inventory.items.at(i).itemCount << 16;
		val &= 0x00FFFFFF;
		val |= 0x00 << 24;
		memcpy(data2 + (i * 4) + (asdf2.length() / 2), &val, 4);
	}
	ENetPacket* packet3 = enet_packet_create(data2,
		packetLen,
		ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packet3);
	delete data2;
	//enet_host_flush(server);
}

void RemoveInventoryItem(int fItemid, int fQuantity, ENetPeer* peer)
{
	std::ifstream iffff("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

	json jj;

	if (iffff.fail()) {
		iffff.close();
		cout << "[!]  RemoveInventoryItem funkcijoje (ofstream dalyje) error: itemid - " << fItemid << ", kiekis - " << fQuantity << endl;

	}
	if (iffff.is_open()) {


	}

	iffff >> jj; //load


	std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
	if (!oo.is_open()) {
		cout << GetLastError() << " RemoveInventoryItem error: itemid - " << fItemid << ", mm - " << fQuantity << endl;
		_getch();
	}

	//jj["items"][aposition]["aposition"] = aposition;


	for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
	{
		int itemid = jj["items"][i]["itemid"];
		int quantity = jj["items"][i]["quantity"];
		if (itemid == fItemid)
		{
			if (quantity - fQuantity == 0)
			{
				jj["items"][i]["itemid"] = 0;
				jj["items"][i]["quantity"] = 0;
			}
			else
			{
				jj["items"][i]["itemid"] = itemid;
				jj["items"][i]["quantity"] = quantity - fQuantity;
			}

			break;
		}

	}
	oo << jj << std::endl;

	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{
		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid)
		{
			if ((unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount > fQuantity && (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount != fQuantity)
			{
				((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount -= fQuantity;
			}
			else
			{
				((PlayerInfo*)(peer->data))->inventory.items.erase(((PlayerInfo*)(peer->data))->inventory.items.begin() + i);
			}
			sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
		}
	}


}

PlayerMoving* unpackPlayerMovingBeta(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	memcpy(&dataStruct->packetType, data, 4);

	return dataStruct;
}

PlayerMoving* unpackPlayerMoving(BYTE* data)
{
	PlayerMoving* dataStruct = new PlayerMoving;
	memcpy(&dataStruct->packetType, data, 4);
	memcpy(&dataStruct->netID, data + 4, 4);
	memcpy(&dataStruct->characterState, data + 12, 4);
	memcpy(&dataStruct->plantingTree, data + 20, 4);
	memcpy(&dataStruct->x, data + 24, 4);
	memcpy(&dataStruct->y, data + 28, 4);
	memcpy(&dataStruct->XSpeed, data + 32, 4);
	memcpy(&dataStruct->YSpeed, data + 36, 4);
	memcpy(&dataStruct->punchX, data + 44, 4);
	memcpy(&dataStruct->punchY, data + 48, 4);
	return dataStruct;
}

void SendPacket(int a1, string a2, ENetPeer* enetPeer)
{
	if (enetPeer)
	{
		ENetPacket* v3 = enet_packet_create(0, a2.length() + 5, 1);
		memcpy(v3->data, &a1, 4);
		//*(v3->data) = (DWORD)a1;
		memcpy((v3->data) + 4, a2.c_str(), a2.length());

		//cout << std::hex << (int)(char)v3->data[3] << endl;
		enet_peer_send(enetPeer, 0, v3);
	}
}

void SendPacketRaw(int a1, void* packetData, size_t packetDataSize, void* a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket* p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE*)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD*)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char*)p->data + 4, packetData, packetDataSize);
			memcpy((char*)p->data + packetDataSize + 4, a4, *((DWORD*)packetData + 13));
			enet_peer_send(peer, 0, p);
		}
		else
		{
			p = enet_packet_create(0, packetDataSize + 5, packetFlag);
			memcpy(p->data, &a1, 4);
			memcpy((char*)p->data + 4, packetData, packetDataSize);
			enet_peer_send(peer, 0, p);
		}
	}
	delete (char*)packetData;
}

void RemoveDroppedItem(ENetPeer* peer, const int obj_id, WorldInfo* world)
{
	if (!world) return;
	for (auto currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
		if (isHere(peer, currentPeer))
		{
			const auto b = new BYTE[56];
			memset(b, 0, 56);
			*reinterpret_cast<int*>(&b[0]) = 0xe;
			*reinterpret_cast<int*>(&b[4]) = -2;
			*reinterpret_cast<int*>(&b[8]) = -1;
			*reinterpret_cast<int*>(&b[20]) = obj_id + 1;
			SendPacketRaw(4, b, 56, nullptr, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}
auto processTakeServer(ENetPeer* peer, const int itemIdx)
{
	auto world = getPlyersWorld(peer);
	if (!world) return -1;
	// ReSharper disable once CppInitializedValueIsAlwaysRewritten
	auto legit = true;
	auto atik = -1;
	for (auto i = 0; i < world->droppedItems.size(); i++)
	{
		if (world->droppedItems.at(i).uid == itemIdx)
		{
			atik = i;
			break;
		}
	}
	legit = atik != -1;
	if (legit)
	{
		try
		{
			//const auto droppedItem = world->droppedItems.at(atik);
			world->droppedItems.erase(world->droppedItems.begin() + atik);
		}
		catch (...)
		{
			return -1;
		}
	}
	return 0;
}




int getPlayersCountInWorld(string name)
{
	int count = 0;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->currentWorld == name)
			count++;
	}
	return count;
}
void onPeerConnect(ENetPeer* peer)
{
	ENetPeer* currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				OnInvisV2(currentPeer, ((PlayerInfo*)(peer->data))->invis, ((PlayerInfo*)(peer->data))->netID);
				OnInvisV2(peer, ((PlayerInfo*)(currentPeer->data))->invis, ((PlayerInfo*)(currentPeer->data))->netID);

				string netIdS = std::to_string(((PlayerInfo*)(currentPeer->data))->netID);
				packet::onspawn(peer, "spawn|avatar\nnetID|" + netIdS + "\nuserID|" + ((PlayerInfo*)(currentPeer->data))->userID + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(currentPeer->data))->x) + "|" + std::to_string(((PlayerInfo*)(currentPeer->data))->y) + "\nname|``" + ((PlayerInfo*)(currentPeer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(currentPeer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(currentPeer->data))->invis) + "\nmstate|0\nsmstate|0\n"); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				string netIdS2 = std::to_string(((PlayerInfo*)(peer->data))->netID);
				packet::onspawn(currentPeer, "spawn|avatar\nnetID|" + netIdS2 + "\nuserID|" + ((PlayerInfo*)(peer->data))->userID + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(((PlayerInfo*)(peer->data))->x) + "|" + std::to_string(((PlayerInfo*)(peer->data))->y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(peer->data))->invis) + "\nmstate|0\nsmstate|0\n"); // ((PlayerInfo*)(server->peers[i].data))->tankIDName
				if (((PlayerInfo*)(peer->data))->invis == false) {
					Player::OnConsoleMessage(currentPeer, "`5<`w" + ((PlayerInfo*)(peer->data))->displayName + "`5 entered, `w" + std::to_string(getPlayersCountInWorld(((PlayerInfo*)(peer->data))->currentWorld)) + "`5 others here>``");
					Player::OnPlayPositioned(currentPeer, "audio/door_open.wav", ((PlayerInfo*)(currentPeer->data))->netID, false, NULL);
				}
			}
		}
	}

}
void SendParticleEffect(ENetPeer* peer, int x, int y, int size, int id, int delay)
{
	PlayerMoving datx;
	datx.packetType = 0x11;
	datx.x = x;
	datx.y = y;
	datx.YSpeed = id;
	datx.XSpeed = size;
	datx.plantingTree = delay;
	SendPacketRaw(4, packPlayerMoving(&datx), 56, nullptr, peer, ENET_PACKET_FLAG_RELIABLE);
}

void updateAllClothes(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			gamepacket_t p(0, ((PlayerInfo*)(peer->data))->netID);
			p.Insert("OnSetClothing");
			p.Insert(((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants);
			p.Insert(((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand);
			p.Insert(((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace);
			p.Insert(((PlayerInfo*)(peer->data))->skinColor);
			p.Insert(((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f);
			p.CreatePacket(currentPeer);

			gamepacket_t p2(0, ((PlayerInfo*)(peer->data))->netID);
			p2.Insert("OnSetClothing");
			p2.Insert(((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants);
			p2.Insert(((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand);
			p2.Insert(((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace);
			p2.Insert(((PlayerInfo*)(peer->data))->skinColor);
			p2.Insert(((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f);
			p2.CreatePacket(peer);
		}
	}
}
void send_state(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->currentWorld == "EXIT") return;
	if (((PlayerInfo*)(peer->data))->cloth_necklace == 4656) ((PlayerInfo*)(peer->data))->haveGeigerRadiation = true;
	const auto info = ((PlayerInfo*)(peer->data));
	const auto netID = info->netID;
	const auto state = getState(info);
	for (auto currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED || currentPeer->data == NULL) continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data{};
			auto water = 125.0f;
			data.packetType = 0x14;
			data.characterState = ((PlayerInfo*)(peer->data))->characterState;
			data.x = 1000;
			if (((PlayerInfo*)(peer->data))->cloth_hand == 366) data.y = -400;
			else data.y = 400;
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 300;
			if (((PlayerInfo*)(peer->data))->cloth_back == 9472) data.YSpeed = 600;
			else if (((PlayerInfo*)(peer->data))->cloth_back == 5196 || ((PlayerInfo*)(peer->data))->cloth_back == 7558) data.YSpeed = 250;
			else data.YSpeed = 1000;
			data.netID = netID;
			data.plantingTree = state;
			const auto raw = packPlayerMoving(&data);
			auto var = ((PlayerInfo*)(peer->data))->effect;
			memcpy(raw + 1, &var, 3);
			memcpy(raw + 16, &water, 4);
			SendPacketRaw(4, raw, 56, nullptr, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}
void sendPuncheffectpeer(ENetPeer* peer, int punch) {
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	int state = getState(info);
	PlayerMoving data;
	float water = 125.0f;
	data.packetType = 0x14;
	data.characterState = ((PlayerInfo*)(peer->data))->characterState; // animation
	data.x = 1000;
	//data.y = 100;
	if (((PlayerInfo*)(peer->data))->cloth_hand == 366) {
		data.y = -400; // - is hbow
	}
	else {
		data.y = 400;
	}
	data.punchX = -1;
	data.punchY = -1;
	data.XSpeed = 300;
	if (((PlayerInfo*)(peer->data))->cloth_back == 1738) {
		data.YSpeed = 600;
	}
	else {
		data.YSpeed = 1150;
	}
	data.netID = netID;
	data.plantingTree = state;
	BYTE* raw = packPlayerMoving(&data);
	int var = punch;
	memcpy(raw + 1, &var, 3);
	memcpy(raw + 16, &water, 4);
	SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	
}

void sendPuncheffect(ENetPeer* peer, int punch) {
	const auto info = (((PlayerInfo*)(peer->data)));
	const auto netID = info->netID;
	const auto state = getState(info);
	for (ENetPeer* currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED || currentPeer->data == NULL) continue;
		if (isHere(peer, currentPeer)) {
			if (peer != currentPeer) {
				PlayerMoving data{};
				data.packetType = 0x14;
				data.characterState = (((PlayerInfo*)(peer->data)))->characterState;
				data.x = 1000;
				data.y = 100;
				data.x = 1000;
				data.y = 1000;
				data.punchX = 0;
				data.punchY = 0;
				data.XSpeed = 300;
				data.YSpeed = 600;
				data.netID = netID;
				data.plantingTree = state;
				const auto raw = packPlayerMoving(&data);
				auto var = punch;
				memcpy(raw + 1, &var, 3);
				SendPacketRaw(4, raw, 56, nullptr, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}
void sendClothes(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	gamepacket_t p(0, ((PlayerInfo*)(peer->data))->netID);
	p.Insert("OnSetClothing");
	p.Insert(((PlayerInfo*)(peer->data))->cloth_hair, ((PlayerInfo*)(peer->data))->cloth_shirt, ((PlayerInfo*)(peer->data))->cloth_pants);
	p.Insert(((PlayerInfo*)(peer->data))->cloth_feet, ((PlayerInfo*)(peer->data))->cloth_face, ((PlayerInfo*)(peer->data))->cloth_hand);
	p.Insert(((PlayerInfo*)(peer->data))->cloth_back, ((PlayerInfo*)(peer->data))->cloth_mask, ((PlayerInfo*)(peer->data))->cloth_necklace);
	p.Insert(((PlayerInfo*)(peer->data))->skinColor);
	p.Insert(((PlayerInfo*)(peer->data))->cloth_ances, 0.0f, 0.0f);
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			p.CreatePacket(currentPeer);
		}

	}
}
void SearchInventoryItem(ENetPeer* peer, int fItemid, int fQuantity, bool& iscontains)
{
	iscontains = false;
	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{
		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount >= fQuantity) {
			iscontains = true;
			break;
		}
	}
}
void updateplayerset(ENetPeer* peer, int targetitem)
{
	int clothitem = ((PlayerInfo*)(peer->data))->cloth_hand;
	int clothface = ((PlayerInfo*)(peer->data))->cloth_face;
	int clothneck = ((PlayerInfo*)(peer->data))->cloth_necklace;
	int clothshirt = ((PlayerInfo*)(peer->data))->cloth_shirt;
	int clothback = ((PlayerInfo*)(peer->data))->cloth_back;
	int clothances = ((PlayerInfo*)(peer->data))->cloth_ances;
	int clothpants = ((PlayerInfo*)(peer->data))->cloth_pants;
	int clothfeet = ((PlayerInfo*)(peer->data))->cloth_feet;
	int clothhair = ((PlayerInfo*)(peer->data))->cloth_hair;
	int clothmask = ((PlayerInfo*)(peer->data))->cloth_mask;
	int item = targetitem;

	if (clothmask == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_mask = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothitem == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_hand = 0;
			sendClothes(peer);
			((PlayerInfo*)(peer->data))->effect = 8421376;
			sendPuncheffectpeer(peer, ((PlayerInfo*)(peer->data))->effect);
		}
		else {

		}
	}

	if (clothface == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_face = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothneck == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_necklace = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothshirt == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_shirt = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothback == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_back = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothances == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_ances = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothpants == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_pants = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothfeet == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_feet = 0;
			sendClothes(peer);
		}
		else {

		}
	}

	if (clothhair == item)
	{
		bool iscontains = false;
		SearchInventoryItem(peer, item, 1, iscontains);
		if (!iscontains)
		{
			((PlayerInfo*)(peer->data))->cloth_hair = 0;
			sendClothes(peer);
		}
		else {

		}
	}
}

void sendPData(ENetPeer* peer, PlayerMoving* data)
{
	ENetPeer* currentPeer;

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (peer != currentPeer)
		{
			if (isHere(peer, currentPeer))
			{
				data->netID = ((PlayerInfo*)(peer->data))->netID;

				SendPacketRaw(4, packPlayerMoving(data), 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}

void autoSaveWorlds()
{
	while (true)
	{
		Sleep(300000);
		ENetPeer* currentPeer;
		for (currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
			gamepacket_t p;
			p.Insert("OnConsoleMessage");
			p.Insert("`Saving server data... (may take up to minute)");
		}
		saveAllWorlds();
	}
}
void sendRoulete(ENetPeer* peer, int x, int y)
{
	ENetPeer* currentPeer;
	int val = rand() % 37;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			gamepacket_t p(2500);
			p.Insert("OnTalkBubble");
			p.Insert(((PlayerInfo*)(peer->data))->netID);
			p.Insert("`w[" + ((PlayerInfo*)(peer->data))->displayName + " `wspun the wheel and got `6" + std::to_string(val) + "`w!]");
			p.Insert(0);
			p.CreatePacket(currentPeer);
		}
	}
}

void packetCount(ENetPeer* peer) {
	using namespace std::chrono;
	if (((PlayerInfo*)(peer->data))->packetsec + 1000 > (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count()) {
		if (((PlayerInfo*)(peer->data))->packetinsec >= 50) {
			enet_peer_reset(peer);
		}
		else {
			((PlayerInfo*)(peer->data))->packetinsec = ((PlayerInfo*)(peer->data))->packetinsec + 1;
		}
	}
	else {
		((PlayerInfo*)(peer->data))->packetsec = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
		((PlayerInfo*)(peer->data))->packetinsec = 0;
	}
}

void sendNothingHappened(ENetPeer* peer, int x, int y) {
	PlayerMoving data;
	data.netID = ((PlayerInfo*)(peer->data))->netID;
	data.packetType = 0x8;
	data.plantingTree = 0;
	data.netID = -1;
	data.x = x;
	data.y = y;
	data.punchX = x;
	data.punchY = y;
	SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}

void loadnews() {
	std::ifstream ifs("news.txt");
	std::string content((std::istreambuf_iterator<char>(ifs)),
		(std::istreambuf_iterator<char>()));

	string target = "\r";
	string news = "";
	int found = -1;
	do {
		found = content.find(target, found + 1);
		if (found != -1) {
			news = content.substr(0, found) + content.substr(found + target.length());
		}
		else {
			news = content;
		}
	} while (found != -1);
	if (news != "") {
		newslist = news;
	}
}
void saveinventorybuild(ENetPeer* peer, int tile) {
	std::ifstream iffff("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
	json jj;
	if (iffff.fail()) {
		iffff.close();
	}
	if (iffff.is_open()) {
	}
	iffff >> jj; //load
	std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
	if (!oo.is_open()) {
		cout << GetLastError() << endl;
		_getch();
	}
	PlayerInventory inventory = ((PlayerInfo*)(peer->data))->inventory;
	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.inventorySize; i++)
	{
		if (i < ((PlayerInfo*)(peer->data))->inventory.items.size())
		{
			jj["items"][i]["itemid"] = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID;
			jj["items"][i]["count"] = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount;
		}
		else
		{
			jj["items"][i]["itemid"] = 0;
			jj["items"][i]["count"] = 0;
		}
	}
	oo << jj << std::endl;
	if (oo.fail()) {
		oo.close();
	}
}


BYTE* packBlockVisual(TileExtra* dataStruct)
{

	BYTE* data = new BYTE[104]; // 96
	for (int i = 0; i < 100; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	//memcpy(data + 40, &dataStruct->bpm, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);


	return data;
}

BYTE* packBlockVisual222(TileExtra* dataStruct)
{

	BYTE* data = new BYTE[104]; // 96
	for (int i = 0; i < 100; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 16, &dataStruct->objectSpeedX, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);


	return data;
}
BYTE* packStuffVisual(TileExtra* dataStruct, int options, int gravity)
{
	BYTE* data = new BYTE[102];
	for (int i = 0; i < 102; i++)
	{
		data[i] = 0;
	}
	memcpy(data, &dataStruct->packetType, 4);
	memcpy(data + 8, &dataStruct->netID, 4);
	memcpy(data + 12, &dataStruct->characterState, 4);
	memcpy(data + 44, &dataStruct->punchX, 4);
	memcpy(data + 48, &dataStruct->punchY, 4);
	memcpy(data + 52, &dataStruct->charStat, 4);
	memcpy(data + 56, &dataStruct->blockid, 2);
	memcpy(data + 58, &dataStruct->backgroundid, 2);
	memcpy(data + 60, &dataStruct->visual, 4);
	memcpy(data + 64, &dataStruct->displayblock, 4);
	memcpy(data + 68, &gravity, 4);
	memcpy(data + 70, &options, 4);

	return data;
}



int getTileState(WorldInfo* world, int x, int y) {
	int blockStateFlags = 0x00000000;
	// type 1 = locked
	if (world->items[x + (y * world->width)].isMultifacing)
		blockStateFlags |= 0x00200000;
	if (world->items[x + (y * world->width)].activated)
		blockStateFlags |= 0x00400000;
	if (world->items[x + (y * world->width)].water)
		blockStateFlags |= 0x04000000;
	if (world->items[x + (y * world->width)].glue)
		blockStateFlags |= 0x08000000;
	if (world->items[x + (y * world->width)].fire)
		blockStateFlags |= 0x10000000;
	if (world->items[x + (y * world->width)].red)
		blockStateFlags |= 0x20000000;
	if (world->items[x + (y * world->width)].green)
		blockStateFlags |= 0x40000000;
	if (world->items[x + (y * world->width)].blue)
		blockStateFlags |= 0x80000000;

	return blockStateFlags;
}
std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}
void updateSign(ENetPeer* peer, int foreground, int background, int x, int y, string text, WorldInfo* world)
{
	//Sign Tag System
	if (text.find("%username%") != string::npos) {
		text = ReplaceAll(text, "%username%", ((PlayerInfo*)(peer->data))->displayNameBackup + "``");
	}
	if (text.find("%worldname%") != string::npos) {
		text = ReplaceAll(text, "%worldname%", ((PlayerInfo*)(peer->data))->currentWorld + "``");
	}
	if (text.find("%gems%") != string::npos) {
		text = ReplaceAll(text, "%gems%", to_string(((PlayerInfo*)(peer->data))->gem) + "``");
	}

	int hmm = 8;
	int text_len = text.length();
	int lol = 0;
	int wut = 5;
	int yeh = hmm + 3 + 1;
	int idk = 15 + text_len;
	int is_locked = 0;
	int bubble_type = 2;
	int ok = 52 + idk;
	int kek = ok + 4;
	int yup = ok - 8 - idk;
	int four = 4;
	int magic = 56;
	int wew = ok + 5 + 4;
	int wow = magic + 4 + 5;

	BYTE* datas = new BYTE[kek];
	ENetPacket* p = enet_packet_create(0, wew, ENET_PACKET_FLAG_RELIABLE);
	for (int i = 0; i < kek; i++) datas[i] = 0;
	memcpy(datas, &wut, four);
	memcpy(datas + yeh, &hmm, four);
	memcpy(datas + yup, &x, 4);
	memcpy(datas + yup + 4, &y, 4);
	memcpy(datas + 4 + yup + 4, &idk, four);
	memcpy(datas + magic, &foreground, 2);
	memcpy(datas + magic + 2, &background, 2);
	memcpy(datas + four + magic, &lol, four);
	memcpy(datas + magic + 4 + four, &bubble_type, 1);
	memcpy(datas + wow, &text_len, 2);
	memcpy(datas + 2 + wow, text.c_str(), text_len);
	memcpy(datas + ok, &is_locked, four);
	memcpy(p->data, &four, four);
	memcpy((char*)p->data + four, datas, kek);

	enet_peer_send(peer, 0, p);
	delete datas;
}
void SendPacketRaw2(int a1, void* packetData, size_t packetDataSize, void* a4, ENetPeer* peer, int packetFlag)
{
	ENetPacket* p;

	if (peer) // check if we have it setup
	{
		if (a1 == 4 && *((BYTE*)packetData + 12) & 8)
		{
			p = enet_packet_create(0, packetDataSize + *((DWORD*)packetData + 13) + 5, packetFlag);
			int four = 4;
			memcpy(p->data, &four, 4);
			memcpy((char*)p->data + 4, packetData, packetDataSize);
			memcpy((char*)p->data + packetDataSize + 4, a4, *((DWORD*)packetData + 13));
			enet_peer_send(peer, 0, p);

		}
		else
		{
			if (a1 == 192) {
				a1 = 4;
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char*)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
			else {
				p = enet_packet_create(0, packetDataSize + 5, packetFlag);
				memcpy(p->data, &a1, 4);
				memcpy((char*)p->data + 4, packetData, packetDataSize);
				enet_peer_send(peer, 0, p);


			}
		}
	}

	delete packetData;
}

void updateTileVisualPeer(ENetPeer* peer, WorldInfo* world, int x, int y) {
	TileExtra data;
	data.packetType = 0x5;
	data.characterState = 8;
	data.charStat = 8;
	data.blockid = world->items[x + (y * world->width)].foreground;
	data.backgroundid = world->items[x + (y * world->width)].background;
	data.visual = getTileState(world, x, y);
	data.punchX = x;
	data.punchY = y;
	data.netID = ((PlayerInfo*)(peer->data))->netID;
	SendPacketRaw2(192, packBlockVisual(&data), 100, 0, peer, ENET_PACKET_FLAG_RELIABLE);
}

void updateTileVisual(ENetPeer* peer, WorldInfo* world, int x, int y, int netID) {

	TileExtra data;
	data.packetType = 0x5;
	data.characterState = 8;
	data.charStat = 8;
	data.blockid = world->items[x + (y * world->width)].foreground;
	data.backgroundid = world->items[x + (y * world->width)].background;
	data.visual = getTileState(world, x, y);
	data.punchX = x;
	data.punchY = y;
	data.netID = netID;
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			SendPacketRaw2(192, packBlockVisual(&data), 100, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}
int getBlockState(WorldItem* worldBlock)
{
	int blockStateFlags = 0x00000000;
	// type 1 = locked

	if (worldBlock->activated)
		blockStateFlags |= 0x00400000;
	if (worldBlock->water)
		blockStateFlags |= 0x04000000;
	if (worldBlock->glue)
		blockStateFlags |= 0x08000000;
	if (worldBlock->fire)
		blockStateFlags |= 0x10000000;
	if (worldBlock->red)
		blockStateFlags |= 0x20000000;
	if (worldBlock->green)
		blockStateFlags |= 0x40000000;
	if (worldBlock->blue)
		blockStateFlags |= 0x80000000;

	return blockStateFlags;
}
void UpdateBlockState(ENetPeer* peer, const int x, const int y, bool forEveryone, WorldInfo* worldInfo)
{
	if (!worldInfo) return;
	const auto i = y * worldInfo->width + x;
	auto blockStateFlags = 0;
	if (worldInfo->items[i].isMultifacing)
		blockStateFlags |= 0x00200000;
	if (worldInfo->items[i].water)
		blockStateFlags |= 0x04000000;
	if (worldInfo->items[i].glue)
		blockStateFlags |= 0x08000000;
	if (worldInfo->items[i].fire)
		blockStateFlags |= 0x10000000;
	if (worldInfo->items[i].red)
		blockStateFlags |= 0x20000000;
	if (worldInfo->items[i].green)
		blockStateFlags |= 0x40000000;
	if (worldInfo->items[i].blue)
		blockStateFlags |= 0x80000000;
	if (worldInfo->items[i].activated)
		blockStateFlags |= 0x00400000;
	if (blockStateFlags != 0)
	{
		TileExtra data;
		data.packetType = 0x5;
		data.characterState = 8;
		data.charStat = 8;
		data.blockid = worldInfo->items[i].foreground;
		data.backgroundid = worldInfo->items[i].background;
		data.visual = blockStateFlags;
		data.punchX = x;
		data.punchY = y;
		for (auto currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
			if (isHere(peer, currentPeer))
			{
				SendPacketRaw2(192, packBlockVisual(&data), 100, nullptr, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
	else
	{
		TileExtra data;
		data.packetType = 0x5;
		data.characterState = 8;
		data.charStat = 8;
		data.blockid = worldInfo->items[i].foreground;
		data.backgroundid = worldInfo->items[i].background;
		data.visual = blockStateFlags;
		data.punchX = x;
		data.punchY = y;
		for (auto currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
			if (isHere(peer, currentPeer))
			{
				SendPacketRaw2(192, packBlockVisual(&data), 100, nullptr, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}
string lockTileDatas(int visual, uint32_t owner, uint32_t adminLength, vector<string> admins, bool isPublic = false, uint8_t bpm = 0) {
	string data;
	data.resize(4 + 6 + 4 + 4 + adminLength * 4 + 8);
	if (bpm) data.resize(data.length() + 4);
	data[2] = 0x01;
	if (isPublic) data[2] |= 0x80;
	data[4] = 3;
	data[5] = visual; // or 0x02
	STRINT(data, 6) = owner;
	STRINT(data, 10) = adminLength;
	for (uint32_t i = 0; i < adminLength; i++) {

	}

	if (bpm) {
		STRINT(data, 10)++;
		STRINT(data, 14 + adminLength * 4) = -bpm;

	}
	return data;
}

string packPlayerMoving2(PlayerMoving* dataStruct)
{
	string data;
	data.resize(56);
	STRINT(data, 0) = dataStruct->packetType;
	STRINT(data, 4) = dataStruct->netID;
	STRINT(data, 12) = dataStruct->characterState;
	STRINT(data, 20) = dataStruct->plantingTree;
	STRINT(data, 24) = *(int*)&dataStruct->x;
	STRINT(data, 28) = *(int*)&dataStruct->y;
	STRINT(data, 32) = *(int*)&dataStruct->XSpeed;
	STRINT(data, 36) = *(int*)&dataStruct->YSpeed;
	STRINT(data, 44) = dataStruct->punchX;
	STRINT(data, 48) = dataStruct->punchY;
	return data;
}
void sendTileData(ENetPeer* peer, int x, int y, int visual, uint16_t fgblock, uint16_t bgblock, string tiledata) {
	PlayerMoving pmov;
	pmov.packetType = 5;
	pmov.characterState = 0;
	pmov.x = 0;
	pmov.y = 0;
	pmov.XSpeed = 0;
	pmov.YSpeed = 0;
	pmov.plantingTree = 0;
	pmov.punchX = x;
	pmov.punchY = y;
	pmov.netID = 0;

	string packetstr;
	packetstr.resize(4);
	packetstr[0] = 4;
	packetstr += packPlayerMoving2(&pmov);
	packetstr[16] = 8;
	packetstr.resize(packetstr.size() + 4);
	STRINT(packetstr, 52 + 4) = tiledata.size() + 4;
	STR16(packetstr, 56 + 4) = fgblock;
	STR16(packetstr, 58 + 4) = bgblock;
	packetstr += tiledata;

	ENetPacket* packet = enet_packet_create(&packetstr[0],
		packetstr.length(),
		ENET_PACKET_FLAG_RELIABLE);

	enet_peer_send(peer, 0, packet);
}

void saveItem(int fItemid, int fQuantity, ENetPeer* peer, bool success)
{
	size_t invsizee = ((PlayerInfo*)(peer->data))->currentInventorySize;
	bool invfull = false;
	bool alreadyhave = false;


	if (((PlayerInfo*)(peer->data))->inventory.items.size() == invsizee) {
		//sendConsoleMsg(peer, "Your inventory is full! please upgrade it on the store.");
		alreadyhave = true;
	}

	bool isFullStock = false;
	bool isInInv = false;
	for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
	{

		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount >= 200) {


			//sendConsoleMsg(peer, "You already reached the max count of the item!");

			isFullStock = true;
		}

		if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount < 200)	isInInv = true;

	}

	if (isFullStock == true || alreadyhave == true)
	{
		success = false;
	}
	else
	{
		success = true;

		std::ifstream iffff("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");

		json jj;

		if (iffff.fail()) {
			iffff.close();


		}
		if (iffff.is_open()) {


		}

		iffff >> jj; //load


		std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
		if (!oo.is_open()) {
			cout << GetLastError() << endl;
			_getch();
		}

		//jj["items"][aposition]["aposition"] = aposition;

		if (isInInv == false)
		{

			for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
			{
				int itemid = jj["items"][i]["itemid"];
				int quantity = jj["items"][i]["count"];

				if (itemid == 0 && quantity == 0)
				{
					jj["items"][i]["itemid"] = fItemid;
					jj["items"][i]["count"] = fQuantity;
					break;
				}

			}
			oo << jj << std::endl;


			InventoryItem item;
			item.itemID = fItemid;
			item.itemCount = fQuantity;
			((PlayerInfo*)(peer->data))->inventory.items.push_back(item);

			sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
		}
		else
		{
			for (int i = 0; i < ((PlayerInfo*)(peer->data))->currentInventorySize; i++)
			{
				int itemid = jj["items"][i]["itemid"];
				int quantity = jj["items"][i]["count"];

				if (itemid == fItemid)
				{
					jj["items"][i]["count"] = quantity + fQuantity;
					break;
				}

			}
			oo << jj << std::endl;


			for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
			{
				if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == fItemid)
				{
					((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount += fQuantity;
					sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
				}
			}

		}
	}
}
void sendResponse(ENetPeer* peer) {
	Player::OnPlayPositioned(peer, "audio/punch_locked.wav", ((PlayerInfo*)(peer->data))->netID, false, NULL);
}
void OnRiftApply(ENetPeer* peer, int colum1, int colum2, int colum3, int colum4, int colum5, int colum6, int berapapacket)
{
	ENetPeer* currentPeer;
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			if (berapapacket == 2)
			{
				GamePacket p3 = packetEnd(appendIntx(appendIntx(appendString(createPacket(), "OnRiftCape"), colum1), colum2));
				memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
				ENetPacket* packet2 = enet_packet_create(p3.data, p3.len, ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p3.data;
			}
			else if (berapapacket == 6)
			{
				GamePacket p3 = packetEnd(appendIntx(appendIntx(appendIntx(appendIntx(appendIntx(appendIntx(appendString(createPacket(), "OnRiftCape"), colum1), colum2), colum3), colum4), colum5), colum6));
				memcpy(p3.data + 8, &(((PlayerInfo*)(peer->data))->netID), 4);
				ENetPacket* packet2 = enet_packet_create(p3.data, p3.len, ENET_PACKET_FLAG_RELIABLE);
				enet_peer_send(currentPeer, 0, packet2);
				delete p3.data;
			}
			else
			{

			}
		}
	}
}
void ApplyLockPacket(WorldInfo* world, ENetPeer* peer, int x, int y, int id, int lockowner) {
	if (lockowner == -3) {
		lockowner = ((PlayerInfo*)(peer->data))->netID;
	}
	int locksize = 0;
	if (id == 202) locksize = 25;
	PlayerMoving pmov;
	pmov.packetType = 0xf;
	pmov.characterState = 0;
	pmov.x = 0;
	pmov.y = 0;
	pmov.XSpeed = 0;
	pmov.YSpeed = 0;
	pmov.plantingTree = id;
	pmov.punchX = x;
	pmov.punchY = y;
	pmov.netID = lockowner;
	byte* pmovp = packPlayerMoving(&pmov);
	byte* packet = new byte[64 + locksize * 2];
	memset(packet, 0, 64 + locksize * 2);
	packet[0] = 4;
	memcpy(packet + 4, pmovp, 56);
	delete pmovp;
	packet[12] = locksize;
	packet[16] = 8;
	int locksz = locksize * 2;
	memcpy(packet + 56, &locksz, 4);
	bool lock_above = false;
	bool mid_lock = false;
	bool mid_low = false;
	bool mid_lowest = false;
	int vidur_ten = 2;
	int vidur = 2;
	int vidur_cia = 2;
	int lock_above_lock = 2;
	int lock_lowers_lock = 2;
	for (int i = 0; i < locksize; i++) {
		if (!lock_above) {
			int fml = y * world->width - 200 + x - 4 + lock_above_lock;
			memcpy(packet + world->height + i * 2, &fml, 2);
			lock_above_lock++;
			if (lock_above_lock >= 7) lock_above = true;
			continue;
		}
		if (mid_lowest) {
			int fml = y * world->width + 200 + x - 4 + lock_lowers_lock;
			memcpy(packet + world->height + i * 2, &fml, 2);
			lock_lowers_lock++;
		}
		else if (mid_low) {
			int fml = y * world->width + 100 + x - 4 + vidur_cia;
			memcpy(packet + world->height + i * 2, &fml, 2);
			vidur_cia++;
			if (vidur_cia >= 7) mid_lowest = true;
		}
		else if (mid_lock) {
			int fml = y * world->width + x - 4 + vidur;
			memcpy(packet + world->height + i * 2, &fml, 2);
			vidur++;
			if (vidur >= 7) mid_low = true;
		}
		else if (lock_above) {
			int fml = y * world->width - 100 + x - 4 + vidur_ten;
			memcpy(packet + world->height + i * 2, &fml, 2);
			vidur_ten++;
			if (vidur_ten >= 7) mid_lock = true;
		}
	}
	ENetPacket* packetenet = enet_packet_create(packet, 64 + locksize * 2, ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packetenet);
	delete packet;
}
bool RestrictedArea_check(WorldInfo* world, const int x, const int y) {
	bool scan_area = false;
	int where_lock_x = -1;
	int where_lock_y = -1;
	bool is_public = false;
	bool can_interact = false;
	for (int i = 0; i < world->width * world->height; i++) {
		if (world->items[i].foreground == 202 || world->items[i].foreground == 204 || world->items[i].foreground == 206 || world->items[i].foreground == 4994) {
			where_lock_x = i % world->width;
			where_lock_y = i / world->width;
			scan_area = true;
			if (x == where_lock_x + 1 && where_lock_y == y) can_interact = true;
			if (x == where_lock_x + 2 && where_lock_y == y) can_interact = true;
			if (x == where_lock_x - 1 && where_lock_y == y) can_interact = true;
			if (x == where_lock_x - 2 && where_lock_y == y) can_interact = true;
			if (y == where_lock_y + 1 && where_lock_x == x) can_interact = true;
			if (y == where_lock_y + 2 && where_lock_x == x) can_interact = true;
			if (y == where_lock_y - 1 && where_lock_x == x) can_interact = true;
			if (y == where_lock_y - 2 && where_lock_x == x) can_interact = true;
			if (x == where_lock_x + 1 && where_lock_y + 1 == y) can_interact = true;
			if (x == where_lock_x + 2 && where_lock_y + 2 == y) can_interact = true;
			if (x == where_lock_x - 1 && where_lock_y - 1 == y) can_interact = true;
			if (x == where_lock_x - 2 && where_lock_y - 2 == y) can_interact = true;
			if (y == where_lock_y + 1 && where_lock_x + 1 == x) can_interact = true;
			if (y == where_lock_y + 2 && where_lock_x + 2 == x) can_interact = true;
			if (y == where_lock_y - 1 && where_lock_x - 1 == x) can_interact = true;
			if (y == where_lock_y - 2 && where_lock_x - 2 == x) can_interact = true;
			if (x == where_lock_x + 1 && where_lock_y - 1 == y) can_interact = true;
			if (x == where_lock_x + 2 && where_lock_y - 2 == y) can_interact = true;
			if (x == where_lock_x - 1 && where_lock_y + 1 == y) can_interact = true;
			if (x == where_lock_x - 2 && where_lock_y + 2 == y) can_interact = true;
			if (y == where_lock_y + 1 && where_lock_x - 1 == x) can_interact = true;
			if (y == where_lock_y + 2 && where_lock_x - 2 == x) can_interact = true;
			if (y == where_lock_y - 1 && where_lock_x + 1 == x) can_interact = true;
			if (y == where_lock_y - 2 && where_lock_x + 2 == x) can_interact = true;
			if (x == where_lock_x + 2 && where_lock_y + 1 == y) can_interact = true;
			if (x == where_lock_x - 2 && where_lock_y - 1 == y) can_interact = true;
			if (x == where_lock_x + 1 && where_lock_y + 2 == y) can_interact = true;
			if (x == where_lock_x - 1 && where_lock_y - 2 == y) can_interact = true;
			if (x == where_lock_x - 1 && where_lock_y + 2 == y) can_interact = true;
			if (x == where_lock_x + 1 && where_lock_y - 2 == y) can_interact = true;
			if (x == where_lock_x + 2 && where_lock_y - 1 == y) can_interact = true;
			if (x == where_lock_x + 2 && where_lock_y + 1 == y) can_interact = true;
			if (x == where_lock_x - 2 && where_lock_y + 1 == y) can_interact = true;
		}
	}

	if (!scan_area) return true;
	if (!can_interact) return true;
	return false;
}
bool isWorldOwner(ENetPeer* peer, WorldInfo* world) {
	return((PlayerInfo*)(peer->data))->rawName == world->owner;
}
void updateEntrance(ENetPeer* peer, int foreground, int x, int y, bool open, int bg, bool updateall) {
	BYTE* data = new BYTE[69];// memset(data, 0, 69);
	for (int i = 0; i < 69; i++) data[i] = 0;
	int four = 4; int five = 5; int eight = 8;
	int huhed = (65536 * bg) + foreground; int loled = 128;

	memcpy(data, &four, 4);
	memcpy(data + 4, &five, 4);
	memcpy(data + 16, &eight, 4);
	memcpy(data + 48, &x, 4);
	memcpy(data + 52, &y, 4);
	memcpy(data + 56, &eight, 4);
	memcpy(data + 60, &foreground, 4);
	memcpy(data + 62, &bg, 4);

	if (open) {
		int state = 0;
		memcpy(data + 66, &loled, 4);
		memcpy(data + 68, &state, 4);
	}
	else {
		int state = 100;
		int yeetus = 25600;
		memcpy(data + 67, &yeetus, 5);
		memcpy(data + 68, &state, 4);
	}
	ENetPacket* p = enet_packet_create(data, 69, ENET_PACKET_FLAG_RELIABLE);

	if (updateall)
	{
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				enet_peer_send(currentPeer, 0, p);
			}
		}
	}
	else
	{
		enet_peer_send(peer, 0, p);
	}
	delete data;
}
void RestartForUpdate()
{
	if (restartForUpdate)
	{
		ofstream ofrest("maintenance.txt");
		ofrest << 1;
		ofrest.close();
		GamePacket p;
		ENetPacket* packet;
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message``: ``Restarting server for update in `415 ``seconds"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(10000);
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message``: ``Restarting server for update in `410 ``seconds"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(10000);
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message``: ``Restarting server for update in `44 ``seconds"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(1000);
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message``: ``Restarting server for update in `43 ``seconds"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(1000);
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "``4Global System Message``: ``Restarting server for update in `42 ``seconds"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(1000);
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message``: ``Restarting server for update in `41 ``second"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(1000);
		p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`4Global System Message : `6 Restarting server for update! See you later!"));
		packet = enet_packet_create(p.data,
			p.len,
			ENET_PACKET_FLAG_RELIABLE);
		enet_host_broadcast(server, 0, packet);
		delete p.data;
		Sleep(2000);
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			enet_peer_disconnect_now(currentPeer, 0);
		}
		saveAllWorlds();
		restartForUpdate = false;
	}
}



static inline void ltrim(string& s)
{
	s.erase(s.begin(), find_if(s.begin(), s.end(), [](int ch) {
		return !isspace(ch);
		}));
}

static inline void rtrim(string& s)
{
	s.erase(find_if(s.rbegin(), s.rend(), [](int ch) {
		return !isspace(ch);
		}).base(), s.end());
}

static inline void trim(string& s)
{
	ltrim(s);
	rtrim(s);
}

static inline string trimString(string s)
{
	trim(s);
	return s;
}

int countSpaces(string& str)
{
	int count = 0;
	int length = str.length();
	for (int i = 0; i < length; i++)
	{
		int c = str[i];
		if (isspace(c))
			count++;
	}
	return count;
}

void removeExtraSpaces(string& str)
{
	int n = str.length();
	int i = 0, j = -1;
	bool spaceFound = false;
	while (++j < n && str[j] == ' ');

	while (j < n)
	{
		if (str[j] != ' ')
		{
			if ((str[j] == '.' || str[j] == ',' ||
				str[j] == '?') && i - 1 >= 0 &&
				str[i - 1] == ' ')
				str[i - 1] = str[j++];
			else
				str[i++] = str[j++];

			spaceFound = false;
		}

		else if (str[j++] == ' ')
		{
			if (!spaceFound)
			{
				str[i++] = ' ';
				spaceFound = true;
			}
		}
	}
	if (i <= 1)
		str.erase(str.begin() + i, str.end());
	else
		str.erase(str.begin() + i, str.end());
}

void sendChatMessage(ENetPeer* peer, int netID, string message)
{
	if (GlobalMaintenance) return;
	if (message.length() == 0) return;

	if (1 > (message.size() - countSpaces(message))) return;
	removeExtraSpaces(message);
	message = trimString(message);

	ENetPeer* currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (((PlayerInfo*)(currentPeer->data))->netID == netID)
			name = ((PlayerInfo*)(currentPeer->data))->displayName;

	}
	string cchat1 = "`w";
	string cchat2 = "`o";
	if (((PlayerInfo*)(peer->data))->adminLevel >= 2) {
		if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
			cchat1 = "`5";
			cchat2 = "`5";
		}
		else {
			cchat1 = "`^";
			cchat2 = "`^";
		}
	}
	gamepacket_t p;
	p.Insert("OnConsoleMessage");
	p.Insert("CP:0_PL:4_OID:_CT:[W]_ `o<`w" + name + "`o> " + cchat2 + message);
	gamepacket_t p2;
	p2.Insert("OnTalkBubble");
	p2.Insert(netID);
	p2.Insert(cchat1 + message);
	p2.Insert(0);
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			p.CreatePacket(currentPeer);
			p2.CreatePacket(currentPeer);
		}
	}
}

void sendWho(ENetPeer* peer)
{
	ENetPeer* currentPeer;
	string name = "";
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer))
		{
			if (((PlayerInfo*)(currentPeer->data))->isGhost)
				continue;

			gamepacket_t p;
			p.Insert("OnTalkBubble");
			p.Insert(((PlayerInfo*)(currentPeer->data))->netID);
			p.Insert(((PlayerInfo*)(currentPeer->data))->displayName);
			p.Insert(1);
			p.CreatePacket(peer);
		}
	}
}

// droping items WorldObjectMap::HandlePacket
/*void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect) {
	for (auto currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data{};
			data.packetType = 14;
			data.x = x;
			data.y = y;
			data.netID = netID;
			data.plantingTree = item;
			float val = count;
			auto val2 = specialEffect;
			const auto raw = packPlayerMoving(&data);
			memcpy(raw + 16, &val, 4);
			memcpy(raw + 1, &val2, 1);
			SendPacketRaw(4, raw, 56, nullptr, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
}*/

void sendDrop(ENetPeer* peer, int netID, int x, int y, int item, int count, BYTE specialEffect, bool onlyForPeer)
{
	WorldInfo* world = getPlyersWorld(peer);
	if (onlyForPeer) {
		PlayerMoving data;
		data.packetType = 14;
		data.x = x;
		data.y = y;
		data.netID = netID;
		data.plantingTree = item;
		float val = count; // item count
		BYTE val2 = specialEffect;

		BYTE* raw = packPlayerMoving(&data);
		memcpy(raw + 16, &val, 4);
		memcpy(raw + 1, &val2, 1);

		SendPacketRaw(4, raw, 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
	}
	else {
		DroppedItem dropItem;
		dropItem.x = x;
		dropItem.y = y;
		dropItem.count = count;
		dropItem.id = item;
		dropItem.uid = world->droppedCount++;
		world->droppedItems.push_back(dropItem);
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				PlayerMoving data;
				data.packetType = 14;
				data.x = x;
				data.y = y;
				data.netID = netID;
				data.plantingTree = item;
				float val = count; // item count
				BYTE val2 = specialEffect;

				BYTE* raw = packPlayerMoving(&data);
				memcpy(raw + 16, &val, 4);
				memcpy(raw + 1, &val2, 1);

				SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
			}
		}
	}
}
//This is only on server. The inventory is automatically updated on the client.
void addItemToInventory(ENetPeer* peer, int id) {
	PlayerInventory inventory = ((PlayerInfo*)(peer->data))->inventory;
	for (int i = 0; i < inventory.items.size(); i++) {
		if (inventory.items[i].itemID == id && inventory.items[i].itemCount < 200) {
			inventory.items[i].itemCount++;
			return;
		}
	}
	if (inventory.items.size() >= inventory.inventorySize)
		return;
	InventoryItem item;
	item.itemCount = 1;
	item.itemID = id;
	inventory.items.push_back(item);
}

int getSharedUID(ENetPeer* peer, int itemNetID) {
	auto v = ((PlayerInfo*)(peer->data))->item_uids;
	for (auto t = v.begin(); t != v.end(); ++t) {
		if (t->actual_uid == itemNetID) {
			return t->shared_uid;
		}
	}
	return 0;
}

int checkForUIDMatch(ENetPeer* peer, int itemNetID) {
	auto v = ((PlayerInfo*)(peer->data))->item_uids;
	for (auto t = v.begin(); t != v.end(); ++t) {
		if (t->shared_uid == itemNetID) {
			return t->actual_uid;
		}
	}
	return 0;
}

void sendCollect(ENetPeer* peer, int netID, int itemNetID) {
	ENetPeer* currentPeer;
	PlayerMoving data;
	data.packetType = 14;
	data.netID = netID;
	data.plantingTree = itemNetID;
	data.characterState = 0;
	// cout << "Request collect: " << std::to_string(itemNetID) << endl;
	WorldInfo* world = getPlyersWorld(peer);
	for (auto m_item = world->droppedItems.begin(); m_item != world->droppedItems.end(); ++m_item) {
		if ((checkForUIDMatch(peer, itemNetID)) == m_item->uid) {
			//cout << "Success!" << endl;
			for (currentPeer = server->peers;
				currentPeer < &server->peers[server->peerCount];
				++currentPeer)
			{
				if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
					continue;
				if (isHere(peer, currentPeer)) {
					data.plantingTree = getSharedUID(currentPeer, m_item->uid);
					BYTE* raw = packPlayerMoving(&data);
					SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
				}
			}
			world->droppedItems.erase(m_item);
			m_item--;
			return;
		}
	}
}

void sendWorld(ENetPeer* peer, WorldInfo* worldInfo)
{
#ifdef TOTAL_LOG
	cout << "Entering a world..." << endl;
#endif
	((PlayerInfo*)(peer->data))->joinClothesUpdated = false;

	string worldName = worldInfo->name;
	int xSize = worldInfo->width;
	int ySize = worldInfo->height;
	int square = xSize * ySize;
	__int16 namelen = worldName.length();

	int alloc = (8 * square);
	int total = 78 + namelen + square + 24 + alloc;

	BYTE* data = new BYTE[total];
	int s1 = 4, s3 = 8, zero = 0;

	memset(data, 0, total);

	memcpy(data, &s1, 1);
	memcpy(data + 4, &s1, 1);
	memcpy(data + 16, &s3, 1);
	memcpy(data + 66, &namelen, 1);
	memcpy(data + 68, worldName.c_str(), namelen);
	memcpy(data + 68 + namelen, &xSize, 1);
	memcpy(data + 72 + namelen, &ySize, 1);
	memcpy(data + 76 + namelen, &square, 2);
	BYTE* blc = data + 80 + namelen;
	for (int i = 0; i < square; i++) {

		int tile = worldInfo->items[i].foreground;
		int tiles = worldInfo->items[i].background;
		//removed cus some of blocks require tile extra and it will crash the world without
		memcpy(blc, &zero, 2);

		memcpy(blc + 2, &worldInfo->items[i].background, 2);
		int type = 0x00000000;
		// type 1 = locked
		if (worldInfo->items[i].isMultifacing)
			type |= 0x00200000;
		if (worldInfo->items[i].water)
			type |= 0x04000000;
		if (worldInfo->items[i].glue)
			type |= 0x08000000;
		if (worldInfo->items[i].fire)
			type |= 0x10000000;
		if (worldInfo->items[i].red)
			type |= 0x20000000;
		if (worldInfo->items[i].green)
			type |= 0x40000000;
		if (worldInfo->items[i].blue)
			type |= 0x80000000;
		if (worldInfo->items[i].activated)
			type |= 0x00400000;
		// int type = 0x04000000; = water
		// int type = 0x08000000 = glue
		// int type = 0x10000000; = fire
		// int type = 0x20000000; = red color
		// int type = 0x40000000; = green color
		// int type = 0x80000000; = blue color
		memcpy(blc + 4, &type, 4);
		blc += 8;
	}

	//int totalitemdrop = worldInfo->dropobject.size();
		//memcpy(blc, &totalitemdrop, 2);

	ENetPacket* packetw = enet_packet_create(data, total, ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, packetw);
	for (int i = 0; i < square; i++) {

		PlayerMoving data;
		//data.packetType = 0x14;
		data.packetType = 0x3;

		//data.characterState = 0x924; // animation
		data.characterState = 0x0; // animation
		data.x = i % worldInfo->width;
		data.y = i / worldInfo->height;
		data.punchX = i % worldInfo->width;
		data.punchY = i / worldInfo->width;
		data.XSpeed = 0;
		data.YSpeed = 0;
		data.netID = -1;
		data.plantingTree = worldInfo->items[i].foreground;
		SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);

		int x = i % xSize, y = i / xSize;
		ENetPeer* currentPeer;
		for (currentPeer = server->peers;
			currentPeer < &server->peers[server->peerCount];
			++currentPeer)
		{
			if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
				continue;
			if (isHere(peer, currentPeer)) {
				if (worldInfo->items[i].isMultifacing == true) {
					worldInfo->items[i].flipped = true;
					UpdateBlockState(peer, x, y, true, worldInfo);
				}
				if (worldInfo->items[i].activated == true) {
					updateTileVisualPeer(currentPeer, worldInfo, x, y);
					updateTileVisualPeer(peer, worldInfo, x, y);
				}
				if (getItemDef(worldInfo->items[i].foreground).blockType == BlockTypes::GATEWAY) {
					updateEntrance(peer, worldInfo->items[i].foreground, x, y, worldInfo->items[i].opened, worldInfo->items[i].background, true);
				}
				if (getItemDef(worldInfo->items[i].foreground).blockType == BlockTypes::SIGN) {
					updateSign(peer, getItemDef(worldInfo->items[i].foreground).id, getItemDef(worldInfo->items[i].background).id, x, y, worldInfo->items[i].sign, worldInfo);
				}
				if (getItemDef(worldInfo->items[i].foreground).blockType == BlockTypes::LOCK) {
					sendTileData(peer, x, y, 0x10, worldInfo->items[i].foreground, worldInfo->items[i].background, lockTileDatas(0x20, atoi(worldInfo->ownerID.c_str()), worldInfo->accessed.size(), worldInfo->accessed, false, 100));
					ApplyLockPacket(worldInfo, peer, x, y, worldInfo->items[i].foreground, atoi(worldInfo->ownerID.c_str()));

				}
			}
		}
	}
	((PlayerInfo*)(peer->data))->currentWorld = worldInfo->name;
	if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
		if (((PlayerInfo*)(peer->data))->cloth_back >= 1) {
			((PlayerInfo*)(peer->data))->canDoubleJump = true;
		}
	}
	string xr; string xd;

	if (worldInfo->isJammed == true || worldInfo->isPunchJam == true || worldInfo->isZombieJam == true) {
		xr += " `w[";
		if (worldInfo->isJammed == true) {
			xd += "`4JAMMED";
			if (worldInfo->isPunchJam == true) {
				xd += "``, ";
			}
			else if (worldInfo->isZombieJam == true) {
				xd += "``, ";
			}
		}
		if (worldInfo->isPunchJam == true) {
			xd += "`2NO-PUNCH";
			if (worldInfo->isZombieJam == true) {
				xd += "``, ";
			}
		}
		if (worldInfo->isZombieJam == true) {
			xd += "`2IMMUNE";
		}
		xr += xd;
		xr += "`w]";
	}
	packet::consolemessage(peer, "`oWorld `w" + worldInfo->name + "" + xr + " `oentered. There are `w" + std::to_string(getPlayersCountInWorld(((PlayerInfo*)(peer->data))->currentWorld) - 1) + " `oother people here, `w" + to_string(((PlayerInfo*)(peer->data))->OnlineNow) + " `oonline.");
	if (worldInfo->owner != "") {
		packet::consolemessage(peer, "`5[`0" + worldInfo->name + " `$World Locked `oby " + getAdminPrefix(worldInfo->owner, false) + "`5]");
	}
	delete data;
	((PlayerInfo*)(peer->data))->item_uids.clear();
	((PlayerInfo*)(peer->data))->last_uid = 1;
	for (int i = 0; i < worldInfo->droppedItems.size(); i++) {
		DroppedItem item = worldInfo->droppedItems[i];
		sendDrop(peer, -1, item.x, item.y, item.id, item.count, 0, true); //pro sendDrop(peer, -1, item.x, item.y, item.id, item.count, 0, true);
	}
}

void sendAction(ENetPeer* peer, int netID, string action)
{
	ENetPeer* currentPeer;
	string name = "";
	gamepacket_t p(0, netID);
	p.Insert("OnAction");
	p.Insert(action);

	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			p.CreatePacket(currentPeer);
		}
	}
}
void sendState(ENetPeer* peer) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	int netID = info->netID;
	ENetPeer* currentPeer;
	int state = getState(info);
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = 0; // animation
			data.x = 8000;
			data.y = 500;
			data.punchX = 0;
			data.punchY = 0;
			data.XSpeed = 800;
			data.YSpeed = -1;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = 0x808000; // placing and breking
			memcpy(raw + 1, &var, 3);
			float waterspeed = 125.0f;
			memcpy(raw + 16, &waterspeed, 4);
			SendPacketRaw(4, raw, 56, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	// TODO
}

void sendState2(ENetPeer* peer, int netID) {
	//return; // TODO
	PlayerInfo* info = ((PlayerInfo*)(peer->data));
	ENetPeer* currentPeer;
	int state = getState(info);
	for (currentPeer = server->peers;
		currentPeer < &server->peers[server->peerCount];
		++currentPeer)
	{
		if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
			continue;
		if (isHere(peer, currentPeer)) {
			PlayerMoving data;
			data.packetType = 0x14;
			data.characterState = 0; // animation
			data.x = 7000;
			data.y = -1;
			data.punchX = 5;
			data.punchY = 7;
			data.XSpeed = 322;
			data.YSpeed = 654;
			data.netID = netID;
			data.plantingTree = state;
			BYTE* raw = packPlayerMoving(&data);
			int var = 0x808000; // placing and breking
			memcpy(raw + 1, &var, 3);
			float waterspeed = 125.0f;
			memcpy(raw + 16, &waterspeed, 4);
			SendPacketRaw(4, raw, 52, 0, currentPeer, ENET_PACKET_FLAG_RELIABLE);
		}
	}
	// TODO
}

void joinWorld(ENetPeer* peer, string name) {
	WorldInfo info = worldDB.get(peer, name);
	((PlayerInfo*)(peer->data))->currentWorld = name;
	sendWorld(peer, &info);
	int x = 3040;
	int y = 736;
	for (int j = 0; j < info.width * info.height; j++)
	{
		if (info.items[j].foreground == 6) {
			x = (j % info.width) * 32;
			y = (j / info.width) * 32;
		}
	}
	((PlayerInfo*)(peer->data))->respawnX = x;
	((PlayerInfo*)(peer->data))->respawnY = y;
	packet::onspawn(peer, "spawn|avatar\nnetID|" + std::to_string(cId) + "\nuserID|" + ((PlayerInfo*)(peer->data))->userID + "\ncolrect|0|0|20|30\nposXY|" + std::to_string(x) + "|" + std::to_string(y) + "\nname|``" + ((PlayerInfo*)(peer->data))->displayName + "``\ncountry|" + ((PlayerInfo*)(peer->data))->country + "\ninvis|" + to_string(((PlayerInfo*)(peer->data))->invis) + "\nmstate|0\nsmstate|0\ntype|local\n");
	((PlayerInfo*)(peer->data))->netID = cId;
	onPeerConnect(peer);
	cId++;
}
void sendWorldOffers(ENetPeer* peer)
{
	if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
		joinWorld(peer, "START");
		return;
	}
	if (((PlayerInfo*)(peer->data))->cursed == true) {
		joinWorld(peer, "HELL");
		return;
	}
	packet::consolemessage(peer, "`oWhere would you like to go? (`w" + to_string(((PlayerInfo*)(peer->data))->OnlineNow) + "`o online)");

	vector<WorldInfo> worlds = worldDB.getRandomWorlds();
	string worldOffers = "default|";
	if (worlds.size() > 0) {
		worldOffers += worlds[0].name;
	}
	int countsss = 55;
	worldOffers += "\nadd_button|Showing: `wRandom Worlds``|_catselect_|0.6|3529161471|\n";
	worldOffers += "\nadd_floater|BETA||0.60|3529161471\n";
	for (int i = 0; i < worlds.size(); i++) {
		if (getPlayersCountInWorld(worlds[i].name) <= 20) {
			countsss += getPlayersCountInWorld(worlds[i].name);
		}
		if (worlds[i].name.find("_") != string::npos || worlds[i].isJammed == true || worlds[i].name == "START" || worlds[i].name == "BETA") {
			//HIDDEN
		}
		else {
			worldOffers += "add_floater|" + worlds[i].name + "|" + std::to_string(getPlayersCountInWorld(worlds[i].name)) + "|0." + to_string(countsss) + "|3529161471\n";
		}
	}
	worldOffers += "\nadd_floater|START||0.80|3529161471\n";
	//GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnRequestWorldSelectMenu"), "default|GO FOR IT\nadd_button|Showing: `wFake Worlds``|_catselect_|0.6|3529161471|\nadd_floater|Subscribe|5|0.55|3529161471\nadd_floater|Growtopia|4|0.52|4278190335\nadd_floater|Noobs|150|0.49|3529161471\nadd_floater|...|3|0.49|3529161471\nadd_floater|`6:O :O :O``|2|0.46|3529161471\nadd_floater|SEEMS TO WORK|2|0.46|3529161471\nadd_floater|?????|1|0.43|3529161471\nadd_floater|KEKEKEKEK|13|0.7|3417414143\n"));
	//for (int i = 0; i < p.len; i++) cout << (int)*(p.data + i) << " ";
	packet::requestworldselectmenu(peer, worldOffers);
}







//replaced X-to-close with a Ctrl+C exit
void exitHandler(int s) {
	saveAllWorlds();
	exit(0);

}

void loadConfig() {
	/*inside config.json:
	{
	"port": 17091,
	"cdn": "0098/CDNContent37/cache/"
	}
	*/


	std::ifstream ifs("config.json");
	if (ifs.is_open()) {
		json j;
		ifs >> j;
		ifs.close();
		try {
			configPort = j["port"].get<int>();
			configCDN = j["cdn"].get<string>();

			cout << "Config loaded." << endl;
		}
		catch (...) {
			cout << "Invalid Config, Fixing..." << endl;
			string config_contents = "{ \"port\": 17091, \"cdn\": \"0098/CDNContent77/cache/\" }";

			ofstream myfile1;
			myfile1.open("config.json");
			myfile1 << config_contents;
			myfile1.close();
			cout << "Config Has Been Fixed! Reloading..." << endl;
			std::ifstream ifs("config.json");
			json j;
			ifs >> j;
			ifs.close();
			configPort = j["port"].get<int>();
			configCDN = j["cdn"].get<string>();

			cout << "Config loaded." << endl;
		}
	}
	else {
		cout << "Config not found, Creating..." << endl;
		string config_contents = "{ \"port\": 17091, \"cdn\": \"0098/CDNContent77/cache/\" }";

		ofstream myfile1;
		myfile1.open("config.json");
		myfile1 << config_contents;
		myfile1.close();
		cout << "Config Has Been Created! Reloading..." << endl;
		std::ifstream ifs("config.json");
		json j;
		ifs >> j;
		ifs.close();
		configPort = j["port"].get<int>();
		configCDN = j["cdn"].get<string>();

		cout << "Config loaded." << endl;
	}
}

long long GetCurrentTimeInternal()
{
	using namespace std::chrono;
	return (duration_cast<microseconds>(system_clock::now().time_since_epoch())).count();
}
long long GetCurrentTimeInternalSeconds()
{
	using namespace std::chrono;
	return (duration_cast<seconds>(system_clock::now().time_since_epoch())).count();
}

template<typename T>
void Remove(std::basic_string<T>& Str, const T* CharsToRemove)
{
	std::basic_string<T>::size_type pos = 0;
	while ((pos = Str.find_first_of(CharsToRemove, pos)) != std::basic_string<T>::npos)
	{
		Str.erase(pos, 1);
	}
}

string OutputBanTime(int n)
{
	string x;
	int day = n / (24 * 3600);
	if (day != 0) x.append(to_string(day) + " Days ");
	n = n % (24 * 3600);
	int hour = n / 3600;
	if (hour != 0) x.append(to_string(hour) + " Hours ");
	n %= 3600;
	int minutes = n / 60;
	if (minutes != 0) x.append(to_string(minutes) + " Minutes ");
	n %= 60;
	int seconds = n;
	if (seconds != 0) x.append(to_string(seconds) + " Seconds");
	return x;
}
int calcBanDuration(long long banDuration) {
	int duration = 0;
	duration = banDuration - GetCurrentTimeInternalSeconds();
	return duration;
}
void banLoginDevice(ENetPeer* peer, const long long banDurationDefault, string sid, string mac)
{
	const auto bantimeleft = calcBanDuration(banDurationDefault);
	if (bantimeleft < 1) return;
	const auto text = "action|log\nmsg|`4Sorry, this device or location is still banned for `w" + OutputBanTime(calcBanDuration(banDurationDefault));
	const string dc = "https://discord.gg/u7rXtkTTBm";
	const auto url = "action|set_url\nurl|" + dc + "\nlabel|Join Growtopia Discord\n";
	const auto data = new BYTE[5 + text.length()];
	const auto dataurl = new BYTE[5 + url.length()];
	BYTE zero = 0;
	auto type = 3;
	memcpy(data, &type, 4);
	memcpy(data + 4, text.c_str(), text.length());
	memcpy(data + 4 + text.length(), &zero, 1);
	memcpy(dataurl, &type, 4);
	memcpy(dataurl + 4, url.c_str(), url.length());
	memcpy(dataurl + 4 + url.length(), &zero, 1);
	const auto p = enet_packet_create(data, 5 + text.length(), ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p);
	const auto p3 = enet_packet_create(dataurl, 5 + url.length(), ENET_PACKET_FLAG_RELIABLE);
	enet_peer_send(peer, 0, p3);
	delete data;
	delete dataurl
		;
	enet_peer_disconnect_later(peer, 0);
}
void checkBan(ENetPeer* peer) {
	string rid = ((PlayerInfo*)(peer->data))->rid;
	string sid = ((PlayerInfo*)(peer->data))->sid;
	string gid = ((PlayerInfo*)(peer->data))->gid;
	string vid = ((PlayerInfo*)(peer->data))->vid;
	string aid = ((PlayerInfo*)(peer->data))->aid;
	string mac = ((PlayerInfo*)(peer->data))->mac;
	string ip = to_string(peer->address.host);
	Remove(mac, ":");
	bool exist = experimental::filesystem::exists("time/bans/rid/" + rid + ".txt") ||
		experimental::filesystem::exists("time/bans/sid/" + sid + ".txt") ||
		experimental::filesystem::exists("time/bans/gid/" + gid + ".txt") ||
		experimental::filesystem::exists("time/bans/vid/" + vid + ".txt") ||
		experimental::filesystem::exists("time/bans/aid/" + aid + ".txt") ||
		experimental::filesystem::exists("time/bans/mac/" + mac + ".txt") ||
		experimental::filesystem::exists("time/bans/ip/" + ip + ".txt");
	if (exist) {
		string content = "0";
		if (experimental::filesystem::exists("time/bans/ip/" + ip + ".txt")) {
			std::ifstream ifs("time/bans/ip/" + ip + ".txt");
			std::string contentf((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			content = contentf;
		}
		else if (experimental::filesystem::exists("time/bans/sid/" + sid + ".txt")) {
			std::ifstream ifs("time/bans/sid/" + sid + ".txt");
			std::string contentf((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			content = contentf;
		}
		else if (experimental::filesystem::exists("time/bans/sid/" + sid + ".txt")) {
			std::ifstream ifs("time/bans/mac/" + mac + ".txt");
			std::string contentf((std::istreambuf_iterator<char>(ifs)),
				(std::istreambuf_iterator<char>()));
			content = contentf;
		}
		if (content != "0") {
			long long banDuration = atoi(content.c_str());
			banLoginDevice(peer, banDuration, sid, mac);
		}
	}
}
WorldInfo* world;
bool isValidID(const string s) {
	return s.find_first_not_of("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") == string::npos;
}
void autoBan(ENetPeer* peer, bool isInvalid, long long timeInH) {
	ofstream x;
	ofstream e;
	ofstream b;
	if (isInvalid) {
		x.open("time/bans/ip/" + to_string(peer->address.host) + ".txt");
		x << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
		x.close();
		enet_peer_disconnect_later(peer, 0);
	}
	else {
		string mac = ((PlayerInfo*)(peer->data))->mac;
		Remove(mac, ":");
		x.open("time/bans/ip/" + to_string(peer->address.host) + ".txt");
		x << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
		x.close();
		if (isValidID(((PlayerInfo*)(peer->data))->sid)) {
			e.open("time/bans/sid/" + ((PlayerInfo*)(peer->data))->sid + ".txt");
			e << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
			e.close();
		}
		if (isValidID(mac)) {
			b.open("time/bans/mac/" + mac + ".txt");
			b << to_string(GetCurrentTimeInternalSeconds() + (timeInH * 3600));
			b.close();
		}

		enet_peer_disconnect_later(peer, 0);
	}
}

void Ban(ENetPeer* peer, bool isInvalid, long long timeInH) {
	ofstream x;
	ofstream e;
	ofstream b;
	if (isInvalid) {
		x.open("time/bans/ip/" + to_string(peer->address.host) + ".txt");
		x << to_string(GetCurrentTimeInternalSeconds() + (timeInH));
		x.close();
		enet_peer_disconnect_later(peer, 0);
	}
	else {
		string mac = ((PlayerInfo*)(peer->data))->mac;
		Remove(mac, ":");
		x.open("time/bans/ip/" + to_string(peer->address.host) + ".txt");
		x << to_string(GetCurrentTimeInternalSeconds() + (timeInH));
		x.close();
		if (isValidID(((PlayerInfo*)(peer->data))->sid)) {
			e.open("time/bans/sid/" + ((PlayerInfo*)(peer->data))->sid + ".txt");
			e << to_string(GetCurrentTimeInternalSeconds() + (timeInH));
			e.close();
		}
		if (isValidID(mac)) {
			b.open("time/bans/mac/" + mac + ".txt");
			b << to_string(GetCurrentTimeInternalSeconds() + (timeInH));
			b.close();
		}

		enet_peer_disconnect_later(peer, 0);
	}
}
bool wrongCmd(ENetPeer* peer) {
	Player::OnConsoleMessage(peer, "`4Unknown command.`` Enter `$/?`` for a list of valid commands.");
	return true;
}

bool OwnerWorld(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->rawName == world->owner) return false;
	else return true;
}
bool isDev(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->adminLevel < 5) {
		Player::OnConsoleMessage(peer, "`4Unknown command.`` Enter `$/?`` for a list of valid commands.");
		return true;
	}
	else return false;
}
bool isCo(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->adminLevel < 4) {
		Player::OnConsoleMessage(peer, "`4Unknown command.`` Enter `$/?`` for a list of valid commands.");
		return true;
	}
	else return false;
}
bool isAdmin(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->adminLevel < 3) {
		Player::OnConsoleMessage(peer, "`4Unknown command.`` Enter `$/?`` for a list of valid commands.");
		return true;
	}
	else return false;
}
bool isMod(ENetPeer* peer) {
	if (((PlayerInfo*)(peer->data))->adminLevel < 2) {
		Player::OnConsoleMessage(peer, "`4Unknown command.`` Enter `$/?`` for a list of valid commands.");
		return true;
	}
	else return false;
}
string randomDuctTapeMessage(size_t length) {
	auto randchar = []() -> char
	{
		const char charset[] =
			"f"
			"m";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}
/*
action|log
msg|`4UPDATE REQUIRED!`` : The `$V2.981`` update is now available for your device.  Go get it!  You'll need to install it before you can play online.
[DBG] Some text is here: action|set_url
url|http://ubistatic-a.akamaihd.net/0098/20180909/GrowtopiaInstaller.exe
label|Download Latest Version
	*/
	//Linux should not have any arguments in main function.
#ifdef _WIN32
int _tmain(int argc, _TCHAR* argv[])
#else
int main()
#endif
{
	cout << "Source By (c) Growtopia Noobs \n(@)ServerName: Project Cold By Time#1010" << endl;

	cout << "Loading config from config.json" << endl;
	loadConfig();

	enet_initialize();
	//Unnecessary save at exit. Commented out to make the program exit slightly quicker.
	if (atexit(saveAllWorlds)) {
		cout << "Worlds won't be saved for this session..." << endl;
	}
	/*if (RegisterApplicationRestart(L" -restarted", 0) == S_OK)
	{
		cout << "Autorestart is ready" << endl;
	}
	else {
		cout << "Binding autorestart failed!" << endl;
	}
	Sleep(65000);
	int* p = NULL;
	*p = 5;*/
	signal(SIGINT, exitHandler);
	ENetAddress address;
	/* Bind the server to the default localhost.     */
	/* A specific host address can be specified by   */
	enet_address_set_host(&address, "0.0.0.0");
	//address.host = ENET_HOST_ANY;
	/* Bind the server to port 1234. */
	address.port = configPort;
	server = enet_host_create(&address /* the address to bind the server host to */,
		1024      /* allow up to 32 clients and/or outgoing connections */,
		2       /* allow up to 2 channels to be used, 0 and 1 */,
		0      /* assume any amount of incoming bandwidth */,
		0      /* assume any amount of outgoing bandwidth */);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);
	cout << "Building items database..." << endl;
	ifstream myFile("items.dat");
	if (myFile.fail()) {
		std::cout << "Items.dat not found!" << endl;
		std::cout << "Please put items.dat in this folder:" << endl;
		system("cd");
		std::cout << "If you dont have items.dat, you can get it from Growtopia cache folder. Please exit." << endl;
		//Sleep(10000);
				//exit(-1);
		while (true); // cross platform solution (Linux pls!)
	}
	buildItemsDatabase();
	cout << "Database is built!" << endl;
	loadnews();
	ENetEvent event;
	/* Wait up to 1000 milliseconds for an event. */
	while (true)
		while (enet_host_service(server, &event, 1000) > 0)
		{
			ENetPeer* peer = event.peer;
			if (peer == NULL || peer == nullptr) {
				continue;
			}
			switch (event.type)
			{
			case ENET_EVENT_TYPE_CONNECT:
			{
#ifdef TOTAL_LOG
				printf("A new client connected.\n");
#endif

				/* Store any relevant client information here. */
				//event.peer->data = "Client information";
				ENetPeer* currentPeer;
				int count = 0;
				for (currentPeer = server->peers;
					currentPeer < &server->peers[server->peerCount];
					++currentPeer)
				{
					if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
						continue;
					if (currentPeer->address.host == peer->address.host)
						count++;
				}

				event.peer->data = new PlayerInfo;
				char clientConnection[16];
				enet_address_get_host_ip(&peer->address, clientConnection, 16);
				((PlayerInfo*)(peer->data))->charIP = clientConnection;

				lastIPLogon = peer->address.host;
				if (peer->address.host == lastIPLogon) {
					using namespace chrono;

					if (lastIPWait + 4000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
					{
						lastIPWait = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
					}
					else {
						Player::OnConsoleMessage(peer, "`oPlease wait 5 seconds before logging on again.``");
						enet_peer_disconnect_later(peer, 0);
					}
				}

				if (count > 3)
				{
					packet::consolemessage(peer, "`oToo many accounts are logged on from this IP. Log off one account before playing please.``");
					enet_peer_disconnect_later(peer, 0);
				}
				else {
					sendData(peer, 1, 0, 0);
				}
				IPNoLoop = peer->address.host;
				continue;
			}
			case ENET_EVENT_TYPE_RECEIVE:
			{
				int messageType = GetMessageTypeFromPacket(event.packet);
				if (((PlayerInfo*)(peer->data))->isIn == false); //checkBan(peer);
				//packetCount(peer);
				WorldInfo* world = getPlyersWorld(peer);
				switch (messageType) {
				case 2:
				{
					//cout << GetTextPointerFromPacket(event.packet) << endl;

					string cch = GetTextPointerFromPacket(event.packet);
					if (cch.size() <= 5) break;
					if (cch == "" || cch == " " || cch == "  " || cch == "   " || cch == "    " || cch == "     " || cch == "      " || cch == "       " || cch == "        " || cch == "        ") break;
					//if (cch.size() > 2048) break;
					ofstream breaklogs("logs.txt", ios::app);
					breaklogs << cch << endl;
					breaklogs.close();
					string str = cch.substr(cch.find("text|") + 5, cch.length() - cch.find("text|") - 1);
					if (cch.find("action|wrench") == 0) {
						std::stringstream ss(cch);
						std::string to;
						int id = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() < 3) continue;
							if (infoDat[1] == "netid") {
								id = atoi(infoDat[2].c_str());
							}

						}
						if (id < 0) continue; //not found

						ENetPeer* currentPeer;
						for (currentPeer = server->peers;
							currentPeer < &server->peers[server->peerCount];
							++currentPeer)
						{
							if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
								continue;
							int isHereOnline = 0;
							if (isHere(peer, currentPeer)) {
								if (((PlayerInfo*)(peer->data))->invis == 0) {
									isHereOnline++;
								}
								else {
									isHereOnline = -1;
								}
								string formatSP;
								string formatEFF;
								//Real gt info dimulai //self wrench
								if (((PlayerInfo*)(peer->data))->haveSuperSupporterName == true) {
									formatSP = "`oYou are a `5Super Supporter `oand have the `wRecycler`o and`w /warp`o.";
								}
								else {
									formatSP = "`oYou are not yet a `2Supporter `oor `5Super Supporter`o.";
								}
								if (((PlayerInfo*)(peer->data))->canWalkInBlocks == true) {
									formatEFF += "\nadd_label_with_icon|small|`wGhost in the Shell: `$I can go through all blocks.|left|8472|";
								}
								if (((PlayerInfo*)(peer->data))->invis == 1) {
									formatEFF += "\nadd_label_with_icon|small|`wInvisible mode: `$I am invisible like a ninja.|left|290|";
								}
								if (((PlayerInfo*)(peer->data))->canDoubleJump == true) {
									formatEFF += "\nadd_label_with_icon|small|`wDouble jump: `$" + getItemDef(((PlayerInfo*)(peer->data))->cloth_back).name + "|left|" + to_string(((PlayerInfo*)(peer->data))->cloth_back) + "|";
								}
								if (((PlayerInfo*)(peer->data))->taped == true && ((PlayerInfo*)(peer->data))->isDuctaped == true) {
									formatEFF += "\nadd_label_with_icon|small|`wDuct tape: `$You can't speak right now.|left|408|";
								}
								if (((PlayerInfo*)(peer->data))->haveBluename == true) {
									formatEFF += "\nadd_label_with_icon|small|`1Blue name: `$Obtained when your level is max.|left|4940|";
								}
								if (((PlayerInfo*)(peer->data))->fastPunch == true) {
									formatEFF += "\nadd_label_with_icon|small|`wFast Punch: `$My hand will destroy everything quickly.|left|18|";
									formatEFF += "\nadd_label_with_icon|small|`wCan't Save World: `$You can't save your world when fast punch is active.|left|32|";
								}
								string formatMORE;
								if (((PlayerInfo*)(peer->data))->AAP == "") {
									formatMORE += "\nadd_button|aapactive|`$Advanced Account Protection|0|0|";
								}
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									formatMORE += "\nadd_button|dev_" + ((PlayerInfo*)(peer->data))->userID + "|`5Developer `wOptions|0|0|";
								}
								if (((PlayerInfo*)(peer->data))->cloth_back == 10424) {
									formatMORE += "\nadd_button|riftcape|`$Rift Cape``|";
								}
								formatMORE += "\nadd_button|achi|`$Achievements``|";
								formatMORE += "\nadd_button|notebook|`wNotebook|0|0|";
								//Real gt info
								if (id == ((PlayerInfo*)(peer->data))->netID) {
									//std::to_string(level)
									int levels = ((PlayerInfo*)(peer->data))->level;
									int xp = ((PlayerInfo*)(peer->data))->xp;
									((PlayerInfo*)(peer->data))->lastUserID = atoi(((PlayerInfo*)(peer->data))->userID.c_str());
									packet::dialog(peer,
										"set_default_color|`o\n\nadd_player_info|`w" + ((PlayerInfo*)(peer->data))->displayName + "|" + std::to_string(levels) + "|" + std::to_string(xp) + "|500||left|32|"
										+ "\nadd_spacer|small|"
										+ formatMORE
										+ "\nadd_spacer|small|"
										+ "\nadd_textbox|`wActive effects: |"
										+ formatEFF
										+ "\nadd_spacer|small|"
										+ "\nadd_textbox|`oYou have `w250 `obackpack slots.|"
										+ "\nadd_textbox|`oCurrent world: `w" + ((PlayerInfo*)(peer->data))->currentWorld + " `o(`w" + to_string(((PlayerInfo*)(peer->data))->x / 32) + "`o,`w " + to_string(((PlayerInfo*)(peer->data))->y / 32) + "`o) (`w" + std::to_string(getPlayersCountInWorld(((PlayerInfo*)(peer->data))->currentWorld)) + "`o person)|"
										+ "\nadd_textbox|" + formatSP + "|"
										+ "\nadd_quick_exit|\nend_dialog|player_info||Close|");
								}
								if (((PlayerInfo*)(currentPeer->data))->netID == id) { //Wrench Orang (Bukan Diri Sendiri)
									string name = ((PlayerInfo*)(currentPeer->data))->displayName;
									((PlayerInfo*)(currentPeer->data))->lastUserID = atoi(((PlayerInfo*)(currentPeer->data))->userID.c_str());
									((PlayerInfo*)(peer->data))->lastUserID = atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str());
									((PlayerInfo*)(peer->data))->lastUser = ((PlayerInfo*)(currentPeer->data))->rawName;
									string modpower;
									if (((PlayerInfo*)(peer->data))->adminLevel >= 2) {
										if (((PlayerInfo*)(peer->data))->adminLevel == 5)
										{
											modpower += "\nadd_button|edit_" + to_string(((PlayerInfo*)(peer->data))->lastUserID) + "|`wEdit Player|0|0|";
										}
										modpower += "\nadd_button|freeze_" + to_string(((PlayerInfo*)(peer->data))->lastUserID) + "|`1Freeze|0|0|\nadd_button|punishview_" + to_string(((PlayerInfo*)(peer->data))->lastUserID) + "|`1Punish/View|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|";
										if (((PlayerInfo*)(peer->data))->rawName == world->owner) {
											modpower += "\nadd_button|wban|`4World Ban|0|0|";
										}
									}
									if (((PlayerInfo*)(peer->data))->rawName == world->owner && ((PlayerInfo*)(peer->data))->adminLevel < 2) {
										packet::dialog(peer, "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_button|trade|`wTrade|0|0|\nadd_textbox|`o(No Battle Leash equipped)|\nadd_textbox|`oYou need a valid license to battle!|\nadd_button|addfriendrnbutton|`wAdd as friend|0|0|\nadd_button|pull|`5Pull|0|0|\nadd_button|kick|`4Kick|0|0|\nadd_button|wban|`4World Ban|0|0|\n\nadd_quick_exit|\nend_dialog|player_info||Close|");
									}
									else {//Player Normal
										packet::dialog(peer, "set_default_color|`o\nadd_label_with_icon|big|`w" + name + "|left|18|\nadd_spacer|small|\nadd_button|trade|Trade|0|0|\nadd_textbox|`o(No Battle Leash equipped)|\nadd_textbox|`oYou need a valid license to battle!|" + modpower + "\nadd_button|addfriendrnbutton|`wAdd as friend|0|0|\n\nadd_quick_exit|\nend_dialog|player_info||Close|");
									}
								}

							}
						}
					}
					if (cch.find("action|setSkin") == 0) {
						if (!world) continue;
						std::stringstream ss(cch);
						std::string to;
						int id = -1;
						string color;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat[0] == "color") color = infoDat[1];
							if (has_only_digits(color) == false) continue;
							id = atoi(color.c_str());
							if (color == "2190853119") {
								id = -2104114177;
							}
							else if (color == "2527912447") {
								id = -1767054849;
							}
							else if (color == "2864971775") {
								id = -1429995521;
							}
							else if (color == "3033464831") {
								id = -1261502465;
							}
							else if (color == "3370516479") {
								id = -924450817;
							}

						}
						((PlayerInfo*)(peer->data))->skinColor = id;
						sendClothes(peer);
					}
					string buyHdrText = "action|buy\nitem|";
					if (cch.find(buyHdrText) == 0)
					{
						PlayerInfo* pInfo = (PlayerInfo*)peer->data;
						string item = cch.substr(buyHdrText.length());
						packet::storepurchaseresult(peer, "The store has not been added, please add it.");
					}
					if (cch.find("action|respawn") == 0)
					{
						if (cch.find("action|respawn_spike") == 0) {
							playerRespawn(peer, true);
						}
						else
						{
							playerRespawn(peer, false);
						}
					}
					if (cch.find("action|friends") == 0)
					{
						if (static_cast<PlayerInfo*>(peer->data)->joinguild == true)
						{
							Player::OnDialogRequest(peer, "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|showguild|Show Guild Members``|0|0|\nend_dialog||OK||\nadd_quick_exit|");
						}
						else
						{
							Player::OnDialogRequest(peer, "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|createguildinfo|Create Guild``|0|0|\nend_dialog||OK||\nadd_quick_exit|");
						}
					}
					if (cch.find("action|growid") == 0)
					{
						SendRegisterDialog(peer);
						enet_host_flush(server);
					}

					else if (cch == "action|store\nlocation|gem\n" || cch == "action|store\nlocation|bottommenu\n" || cch == "action|buy\nitem|main\n" || cch == "action|storenavigate\nitem|main\nselection|gems_rain\n") {
						if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
							SendRegisterDialog(peer);
							break;
						}
						try {
							string items_here = "";
							/*IOTM*/
							items_here += "\nadd_button|itemomonth|`oItem Of The Month``|interface/large/store_buttons/store_buttons16.rttex|July 2021:`` `9Soul Scythe``!<CR><CR>`2You Get:`` 1 `9Soul Scythe``.<CR><CR>`5Description:`` Latest Growtopia Item Of The Month!|0|3|350000|0||interface/large/gui_store_button_overlays1.rttex|0|0||-1|-1||1|||||||";
							items_here += "\nadd_banner|interface/large/gui_shop_featured_header.rttex|0|3|";
							/*365d subs*/
							items_here += "\nadd_button|365d|`o1-Year Subscription Token``|interface/large/store_buttons/store_buttons22.rttex|rt_grope_subs_bundle02|0|5|0|0|||-1|-1||-1|-1|`2You Get:`` 1x 1-Year Subscription Token and 25 Growtokens.<CR><CR>`5Description:`` One full year of special treatment AND 25 Growtokens upfront! You'll get 70 season tokens (as long as there's a seasonal clash running), and 2500 gems every day and a chance of doubling any XP earned, growtime reduction on all seeds planted and Exclusive Skins!|1|3|5000000|0|||-1|-1||-1|-1||1||||||0|";
							items_here += "|\nadd_button|30d|`o30-Day Subscription Token``|interface/large/store_buttons/store_buttons22.rttex|rt_grope_subs_bundle01|0|4|0|0|||-1|-1||-1|-1|`2You Get:`` 1x 30-Day Free Subscription Token and 2 Growtokens.<CR><CR>`5Description:`` 30 full days of special treatment AND 2 Growtokens upfront! You'll get 70 season tokens (as long as there's a seasonal clash running), and 2500 gems every day and a chance of doubling any XP earned, growtime reduction on all seeds planted and Exclusive Skins!|1|3|1000000|0|||-1|-1||-1|-1||1||||||0|";
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|Welcome to the `2Growtopia Store``! Select the item you'd like more info on.`o `wWant to get `5Supporter`` status? Any Gem purchase (or `57,000`` Gems earned with free `5Tapjoy`` offers) will make you one. You'll get new skin colors, the `5Recycle`` tool to convert unwanted items into Gems, and more bonuses!\nenable_tabs|1\nadd_tab_button|main_menu|Home|interface/large/btn_shop2.rttex||1|0|0|0||||-1|-1|||0|\nadd_tab_button|locks_menu|Locks And Stuff|interface/large/btn_shop2.rttex||0|1|0|0||||-1|-1|||0|\nadd_tab_button|itempack_menu|Item Packs|interface/large/btn_shop2.rttex||0|3|0|0||||-1|-1|||0|\nadd_tab_button|bigitems_menu|Awesome Items|interface/large/btn_shop2.rttex||0|4|0|0||||-1|-1|||0|\nadd_tab_button|weather_menu|Weather Machines|interface/large/btn_shop2.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|5|0|0||||-1|-1|||0|\nadd_tab_button|token_menu|Growtoken Items|interface/large/btn_shop2.rttex||0|2|0|0||||-1|-1|||0|" + items_here + ""));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						catch (const std::out_of_range& e) {
							std::cout << e.what() << std::endl;
						}
						break;
					}
					if (cch == "action|buy\nitem|token\n") {
						auto KiekTuri = 0;
						try {
							for (auto i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++) {
								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == 1486 && ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount >= 1) {
									KiekTuri = ((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount;
									break;
								}
							}
						}
						catch (const std::out_of_range& e) {
							std::cout << e.what() << std::endl;
						}
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|`2Spend your Growtokens!`` (You have `5" + to_string(KiekTuri) + "``) You earn Growtokens from Crazy Jim and Sales-Man. Select the item you'd like more info on, or BACK to go back.\nenable_tabs|1\nadd_tab_button|main_menu|Home|interface/large/btn_shop2.rttex||0|0|0|0||||-1|-1|||0|\nadd_tab_button|locks_menu|Locks And Stuff|interface/large/btn_shop2.rttex||0|1|0|0||||-1|-1|||0|\nadd_tab_button|itempack_menu|Item Packs|interface/large/btn_shop2.rttex||0|3|0|0||||-1|-1|||0|\nadd_tab_button|bigitems_menu|Awesome Items|interface/large/btn_shop2.rttex||0|4|0|0||||-1|-1|||0|\nadd_tab_button|weather_menu|Weather Machines|interface/large/btn_shop2.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|5|0|0||||-1|-1|||0|\nadd_tab_button|token_menu|Growtoken Items|interface/large/btn_shop2.rttex||1|2|0|0||||-1|-1|||0|\nadd_button|challenge_timer|`oChallenge Timer``|interface/large/store_buttons/store_buttons15.rttex|`2You Get:`` 1 Challenge Timer.<CR><CR>`5Description:`` Get more people playing your parkours with this secure prize system. You'll need a `#Challenge Start Flag`` and `#Challenge End Flag`` as well (not included). Stock prizes into the Challenge Timer, set a time limit, and watch as players race from start to end. If they make it in time, they win a prize!|0|5|-5|0|||-1|-1||-1|-1||1||||||0|\nadd_button|xp_potion|`oExperience Potion``|interface/large/store_buttons/store_buttons9.rttex|`2You Get:`` 1 Experience Potion.<CR><CR>`5Description:`` This `#Untradeable`` delicious fizzy drink will make you smarter! 10,000 XP smarter instantly, to be exact.|0|2|-10|0|||-1|-1||-1|-1||1||||||0|\nadd_button|megaphone|`oMegaphone``|interface/large/store_buttons/store_buttons15.rttex|`2You Get:`` 1 Megaphone.<CR><CR>`5Description:`` You like broadcasting messages, but you're not so big on spending gems? Buy a Megaphone with Growtokens! Each Megaphone can be used once to send a super broadcast to all players in the game.|0|7|-10|0|||-1|-1||-1|-1||1||||||0|\nadd_button|growmoji_pack|`oGrowmoji Mystery Box``|interface/large/store_buttons/store_buttons19.rttex|`2You Get:`` 1 Growmoji.<CR><CR>`5Description:`` Express yourself! This mysterious box contains one of five fun growmojis you can use to spice up your chat! Which will you get?|0|1|-15|0|||-1|-1||-1|-1||1||||||0|\nadd_button|mini_mod|`oMini-Mod``|interface/large/store_buttons/store_buttons17.rttex|`2You Get:`` 1 Mini-Mod.<CR><CR>`5Description:`` Oh no, it's a Mini-Mod! Punch him to activate (you'll want to punch him!). When activated, he won't allow anyone to drop items in your world.|0|0|-20|0|||-1|-1||-1|-1||1||||||0|\nadd_button|derpy_star|`oDerpy Star Block``|interface/large/store_buttons/store_buttons10.rttex|`2You Get:`` 1 Derpy Star Block.<CR><CR>`5Description:`` DER IM A SUPERSTAR. This is a fairly ordinary block, except for the derpy star on it. Note: it is not permanent, and it doesn't drop seeds. So use it wisely!|0|3|-30|0|||-1|-1||-1|-1||1||||||0|\nadd_button|dirt_gun|`oBLYoshi's Free Dirt``|interface/large/store_buttons/store_buttons13.rttex|`2You Get:`` 1 BLYoshi's Free Dirt.<CR><CR>`5Description:`` 'Free' might be stretching it, but hey, once you buy this deadly rifle, you can spew out all the dirt you want for free! Note: the dirt is launched at high velocity and explodes on impact. Sponsored by BLYoshi.|0|4|-40|0|||-1|-1||-1|-1||1||||||0|\nadd_button|nothingness|`oWeather Machine - Nothingness``|interface/large/store_buttons/store_buttons9.rttex|`2You Get:`` 1 Weather Machine - Nothingness.<CR><CR>`5Description:`` Tired of all that fancy weather?  This machine will turn your world completely black. Yup, that's it. Not a single pixel in the background except pure blackness.|0|3|-50|0|||-1|-1||-1|-1||1||||||0|\nadd_button|spike_juice|`oSpike Juice``|interface/large/store_buttons/store_buttons10.rttex|`2You Get:`` 1 Spike Juice.<CR><CR>`5Description:`` It's fresh squeezed, with little bits of spikes still in it! Drinking this `#Untradeable`` one-use potion will make you immune to Death Spikes and Lava for 5 seconds.|0|5|-60|0|||-1|-1||-1|-1||1||||||0|\nadd_button|doodad|`oDoodad``|interface/large/store_buttons/store_buttons9.rttex|`2You Get:`` 1 Doodad.<CR><CR>`5Description:`` I have no idea what this thing does. It's something electronic? Maybe?|0|5|-75|0|||-1|-1||-1|-1||1||||||0|\nadd_button|crystal_cape|`oCrystal Cape``|interface/large/store_buttons/store_buttons11.rttex|`2You Get:`` 1 Crystal Cape.<CR><CR>`5Description:`` This cape is woven of pure crystal, which makes it pretty uncomfortable. But it also makes it magical! It lets you double-jump off of an imaginary Crystal Block in mid-air. Sponsored by Edvoid20, HemeTems, and Aboge.|0|5|-90|0|||-1|-1||-1|-1||1||||||0|\nadd_button|focused_eyes|`oFocused Eyes``|interface/large/store_buttons/store_buttons9.rttex|`2You Get:`` 1 Focused Eyes.<CR><CR>`5Description:`` This `#Untradeable`` item lets you shoot electricity from your eyes! Wear them with pride, and creepiness.|0|4|-100|0|||-1|-1||-1|-1||1||||||0|\nadd_button|grip_tape|`oGrip Tape``|interface/large/store_buttons/store_buttons14.rttex|`2You Get:`` 1 Grip Tape.<CR><CR>`5Description:`` This is handy for wrapping around the handle of a weapon or tool. It can improve your grip, as well as protect you from cold metal handles. If you aren't planning to craft a weapon that requires Grip Tape, this does you no good at all!|0|5|-100|0|||-1|-1||-1|-1||1||||||0|\nadd_button|cat_eyes|`oCat Eyes``|interface/large/store_buttons/store_buttons23.rttex|`2You Get:`` 1 Cat Eyes.<CR><CR>`5Description:`` Wow, pawesome! These new eyes are the cat's meow, and the purrfect addition to any style.|0|5|-100|0|||-1|-1||-1|-1||1||||||0|\nadd_button|night_vision|`oNight Vision Goggles``|interface/large/store_buttons/store_buttons15.rttex|`2You Get:`` 1 Night Vision Goggles.<CR><CR>`5Description:`` Scared of the dark? We have a solution. You can wear these goggles just to look cool, but if you also happen to have a D Battery (`4batteries not included``) on you, you will be able to see through darkness like it's not even there! Each D Battery can power your goggles for 1 minute. `2If you are in a world you own, the goggles will not require batteries!`` Note: you can't turn the goggles off without removing them, so you'll be wasting your battery if you wear them in daylight while carrying D Batteries.|0|3|-110|0|||-1|-1||-1|-1||1||||||0|\nadd_button|muddy_pants|`oMuddy Pants``|interface/large/store_buttons/store_buttons12.rttex|`2You Get:`` 1 Muddy Pants.<CR><CR>`5Description:`` Well, this is just a pair of muddy pants. But it does come with a super secret bonus surprise that is sure to blow your mind!|0|7|-125|0|||-1|-1||-1|-1||1||||||0|\nadd_button|piranha|`oCuddly Piranha``|interface/large/store_buttons/store_buttons10.rttex|`2You Get:`` 1 Cuddly Piranha.<CR><CR>`5Description:`` This friendly pet piranha won't stay in its bowl!  It just wants to snuggle with your face!|0|0|-150|0|||-1|-1||-1|-1||1||||||0|\nadd_button|puddy_leash|`oPuddy Leash``|interface/large/store_buttons/store_buttons11.rttex|`2You Get:`` 1 Puddy Leash.<CR><CR>`5Description:`` Puddy is a friendly little kitten who will follow you around forever.|0|7|-180|0|||-1|-1||-1|-1||1||||||0|\nadd_button|golden_axe|`oGolden Pickaxe``|interface/large/store_buttons/store_buttons9.rttex|`2You Get:`` 1 Golden Pickaxe.<CR><CR>`5Description:`` Get your own sparkly pickaxe! This `#Untradeable`` item is a status symbol! Oh sure, it isn't any more effective than a normal pickaxe, but it sparkles!|0|1|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|puppy_leash|`oPuppy Leash``|interface/large/store_buttons/store_buttons11.rttex|`2You Get:`` 1 Puppy Leash.<CR><CR>`5Description:`` Get your own pet puppy! This little dog will follow you around forever, never wavering in her loyalty, thus making her `#Untradeable``.|0|4|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|diggers_spade|`oDigger's Spade``|interface/large/store_buttons/store_buttons13.rttex|`2You Get:`` 1 Digger's Spade.<CR><CR>`5Description:`` This may appear to be a humble shovel, but in fact it is enchanted with the greatest magic in Growtopia. It can smash Dirt or Cave Background in a single hit! Unfortunately, it's worthless at digging through anything else. Note: The spade is `#UNTRADEABLE``.|0|7|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|meow_ears|`oMeow Ears``|interface/large/store_buttons/store_buttons22.rttex|`2You Get:`` 1 Meow Ears.<CR><CR>`5Description:`` Meow's super special ears that everyone can now get! Note: These ears are `#UNTRADEABLE``.|0|0|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|frosty_hair|`oFrosty Hair``|interface/large/store_buttons/store_buttons23.rttex|`2You Get:`` 1 Frosty Hair.<CR><CR>`5Description:`` Coldplay is cold, but you can be freezing! Note: The frosty hair is `#UNTRADEABLE``.|0|0|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|zerkon_helmet|`oEvil Space Helmet``|interface/large/store_buttons/store_buttons21.rttex|`2You Get:`` 1 Evil Space Helmet.<CR><CR>`5Description:`` Zerkon commands a starship too small to actually board - pah, time to rule the galaxy properly! Note: The evil space helmet is `#UNTRADEABLE``.|0|6|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|seils_magic_orb|`oSeil's Magic Orbs``|interface/large/store_buttons/store_buttons21.rttex|`2You Get:`` 1 Seil's Magic Orbs.<CR><CR>`5Description:`` Seil is some kind of evil wizard, now you can be too! Note: These magic orbs are `#UNTRADEABLE``.|0|7|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|atomic_shadow_scythe|`oAtomic Shadow Scythe``|interface/large/store_buttons/store_buttons21.rttex|`2You Get:`` 1 Atomic Shadow Scythe.<CR><CR>`5Description:`` AtomicShadow might actually be evil, now you can try it out! Note: The shadow scythe is `#UNTRADEABLE``.|0|5|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|poseidon_diggers_trident|`oPoseidon's Digger's Trident``|interface/large/store_buttons/store_buttons25.rttex|`2You Get:`` 1 Poseidon's Digger's Trident.<CR><CR>`5Description:`` A gift from the gods. This may appear to be a humble trident, but in fact it has the power of Poseidon himself. It can smash `8Deep Sand`` or `8Ocean Rock`` in a single hit. Unfortunately, you don't get to wield the full might of Poseidon... the trident is worthless at smashing anything else. Note: The trident is `#UNTRADEABLE``.|0|6|-200|0|||-1|-1||-1|-1||1||||||0|\nadd_button|grow_boy|`oGrowBoy``|interface/large/store_buttons/store_buttons32.rttex|`2You Get:`` 1 Growboy.<CR><CR>`5Description:`` Bask in the nostalgic green screened goodness of the Growboy! A portable gaming device that packs a punch. Now you're playing with GrowPower! Note: The Growboy is `#UNTRADEABLE``.|0|2|-100|0|||-1|-1||-1|-1||1||||||0|\nadd_button|tsed|`oTactical Stealth Espionage Device``|interface/large/store_buttons/store_buttons32.rttex|`2You Get:`` 1 Tactical Stealth Espionage Device.<CR><CR>`5Description:`` This is Growtech's latest innovation on tactical espionage! Using the latest in scientific breakthroughs this device allows you to seamlessly disguise yourself as... a cardboard box! Note: The Tactical Stealth Espionage Device is `#UNTRADEABLE``.|0|1|-150|0|||-1|-1||-1|-1||1||||||0|\nadd_button|really_dangerous_pet_llama|`oReally Dangerous Pet Llama``|interface/large/store_buttons/store_buttons32.rttex|`2You Get:`` 1 Really Dangerous Pet Llama.<CR><CR>`5Description:`` This Llama is ready for anything Growtopia throws at it! Armed with a silo of Growtech Missiles, experimental Growtech hardened steel armor and a rather snazzy helmet (Llama's own) this Llama is Dangerous with a capital D! Note: This Really Dangerous Pet Llama is `#UNTRADEABLE``.|0|0|-200|0|||-1|-1||-1|-1||1||||||0|"));
						ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (cch == "action|buy\nitem|itempack\n") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|`2Item Packs!``  Select the item you'd like more info on, or BACK to go back.\nenable_tabs|1\nadd_tab_button|main_menu|Home|interface/large/btn_shop2.rttex||0|0|0|0||||-1|-1|||0|\nadd_tab_button|locks_menu|Locks And Stuff|interface/large/btn_shop2.rttex||0|1|0|0||||-1|-1|||0|\nadd_tab_button|itempack_menu|Item Packs|interface/large/btn_shop2.rttex||1|3|0|0||||-1|-1|||0|\nadd_tab_button|bigitems_menu|Awesome Items|interface/large/btn_shop2.rttex||0|4|0|0||||-1|-1|||0|\nadd_tab_button|weather_menu|Weather Machines|interface/large/btn_shop2.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|5|0|0||||-1|-1|||0|\nadd_tab_button|token_menu|Growtoken Items|interface/large/btn_shop2.rttex||0|2|0|0||||-1|-1|||0|\nadd_button|world_lock|`oWorld Lock``|interface/large/store_buttons/store_buttons.rttex|`2You Get:`` 1 World Lock.<CR><CR>`5Description:`` Become the undisputed ruler of your domain with one of these babies.  It works like a normal lock except it locks the `$entire world``!  Won't work on worlds that other people already have locks on. You can even add additional normal locks to give access to certain areas to friends. `5It's a perma-item, is never lost when destroyed.``  `wRecycles for 200 Gems.``|0|7|1000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|world_lock_10_pack|`oWorld Lock Pack``|interface/large/store_buttons/store_buttons18.rttex|`2You Get:`` 10 World Locks.<CR><CR>`5Description:`` 10-pack of World Locks. Become the undisputed ruler of up to TEN kingdoms with these babies. Each works like a normal lock except it locks the `$entire world``!  Won't work on worlds that other people already have locks on. You can even add additional normal locks to give access to certain areas to friends. `5It's a perma-item, is never lost when destroyed.`` `wEach recycles for 200 Gems.``|0|3|10000|0|||-1|-1||-1|-1||1||||||0|"));
						ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (cch == "action|buy\nitem|weather\n") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|`2Weather Machines!``  Select the item you'd like more info on, or BACK to go back.\nenable_tabs|1\nadd_tab_button|main_menu|Home|interface/large/btn_shop2.rttex||0|0|0|0||||-1|-1|||0|\nadd_tab_button|locks_menu|Locks And Stuff|interface/large/btn_shop2.rttex||0|1|0|0||||-1|-1|||0|\nadd_tab_button|itempack_menu|Item Packs|interface/large/btn_shop2.rttex||0|3|0|0||||-1|-1|||0|\nadd_tab_button|bigitems_menu|Awesome Items|interface/large/btn_shop2.rttex||0|4|0|0||||-1|-1|||0|\nadd_tab_button|weather_menu|Weather Machines|interface/large/btn_shop2.rttex|Tired of the same sunny sky?  We offer alternatives within...|1|5|0|0||||-1|-1|||0|\nadd_tab_button|token_menu|Growtoken Items|interface/large/btn_shop2.rttex||0|2|0|0||||-1|-1|||0|\nadd_button|vegas_pack|`oVegas Pack``|interface/large/store_buttons/store_buttons4.rttex|`2You Get:`` 10 Neon Lights, 1 Card Block Seed, 1 `#Rare Pink Cadillac`` 4 Flipping Coins, 1 Dice Block, 1 Gamblers Visor, 1 Slot Machine, 1 Roulette Wheel and 1 Showgirl Hat, 1 Showgirl top and 1 Showgirl Leggins.<CR><CR>`5Description:`` What happens in Growtopia stays in Growtopia!|0|5|20000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|farm_pack|`oFarm Pack``|interface/large/store_buttons/store_buttons5.rttex|`2You Get:`` 1 Chicken, 1 Cow, 100 Wooden Platform, 40 Chandelier, 40 Laser Grid, 60 Sugar Cane, 75 Pepper Tree, 1 `#Rare`` `2Dear John Tractor``.<CR><CR>`5Description:`` Put the `2Grow`` in Growtopia with this pack, including a Cow you can milk, a Chicken that lays eggs and a farmer's outfit. Best of all? You get a `#Rare`` `2Dear John Tractor`` you can ride that will mow down trees!|0|0|15000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|science_pack|`oMad Science Kit``|interface/large/store_buttons/store_buttons5.rttex|`2You Get:`` 1 Science Station, 1 Laboratory, 1 LabCoat, 1 Combover Hair, 1 Goggles, 5 Chemical R, 10 Chemical G, 5 Chemical Y, 5 Chemical B, 5 Chemical P and 1 `#Rare`` `2Death Ray``.<CR><CR>`5Description:`` It's SCIENCE! Defy the natural order with a Science Station that produces chemicals, a Laboratory in which to mix them and a full outfit to do so safely! You'll also get a starter pack of assorted chemicals. Mix them up! Special bonus: A `#Rare`` `2Death Ray`` to make your science truly mad!|0|3|5000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|city_pack|`oCity Pack``|interface/large/store_buttons/store_buttons6.rttex|`2You Get:`` 10 Sidewalks, 3 Street Signs, 3 Streetlamps, 10 Gothic Building tiles, 10 Tenement Building tiles, 10 Fire Escapes, 3 Gargoyles, 10 Hedges, 1 Blue Mailbox, 1 Fire Hydrant and A `#Rare`` `2ATM Machine``.<CR><CR>`5Description:`` Life in the big city is rough but a `#Rare`` `2ATM Machine`` that dishes out gems once a day is very nice!|0|0|8000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|west_pack|`oWild West Pack``|interface/large/store_buttons/store_buttons6.rttex|`2You Get:`` 1 Cowboy Hat, 1 Cowboy Boots, 1 War Paint, 1 Face Bandana, 1 Sheriff Vest, 1 Layer Cake Dress, 1 Corset, 1 Kansas Curls, 10 Western Building 1 Saloon Doors, 5 Western Banners, 1 Buffalo, 10 Rustic Fences, 1 Campfire and 1 Parasol.<CR><CR>`5Description:`` Yippee-kai-yay! This pack includes everything you need to have wild time in the wild west! The Campfire plays cowboy music, and the `#Parasol`` lets you drift down slowly. Special bonus: A `#Rare`` `2Six Shooter`` to blast criminals with!|0|2|8000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|firefighter|`oFirefighter Pack``|interface/large/store_buttons/store_buttons14.rttex|`2You Get:`` 1 Yellow Helmet, 1 Yellow Jacket, 1 Yellow Pants, 1 Firemans Boots, 1 Fire Hose, and 1 `#Rare Firehouse``.<CR><CR>`5Description:`` Rescue Growtopians from the fire! Includes a full Yellow Firefighter Outfit, Fire Hose and a `#Rare Firehouse``, which will protect your own world from fires.|0|1|10000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|paintbrush|`oPainter's Pack``|interface/large/store_buttons/store_buttons15.rttex|`2You Get:`` 1 `#Rare Paintbrush`` and 20 Random Colored Paint Buckets.<CR><CR>`5Description:`` Want to paint your world? This pack includes 20 buckets of random paint colors (may include Varnish, to clean up your messes)! You can paint any block in your world different colors to personalize it.|0|1|30000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|paleo_kit|`oPaleontologist's Kit``|interface/large/store_buttons/store_buttons16.rttex|`2You Get:`` 5 Fossil Brushes, 1 Rock Hammer, 1 Rock Chisel, 1 Blue Hardhat and 1 `#Rare Fossil Prep Station``.<CR><CR>`5Description:`` If you want to dig up fossils, this is the kit for you! Includes everything you need! Use the prepstation to get your fossils ready for display.|0|0|20000|0|||-1|-1||-1|-1||1||||||0|"));
						ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (cch == "action|buy\nitem|bigitems\n") {
						GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStoreRequest"), "set_description_text|`2Awesome Items!``  Select the item you'd like more info on, or BACK to go back.\nenable_tabs|1\nadd_tab_button|main_menu|Home|interface/large/btn_shop2.rttex||0|0|0|0||||-1|-1|||0|\nadd_tab_button|locks_menu|Locks And Stuff|interface/large/btn_shop2.rttex||0|1|0|0||||-1|-1|||0|\nadd_tab_button|itempack_menu|Item Packs|interface/large/btn_shop2.rttex||0|3|0|0||||-1|-1|||0|\nadd_tab_button|bigitems_menu|Awesome Items|interface/large/btn_shop2.rttex||1|4|0|0||||-1|-1|||0|\nadd_tab_button|weather_menu|Weather Machines|interface/large/btn_shop2.rttex|Tired of the same sunny sky?  We offer alternatives within...|0|5|0|0||||-1|-1|||0|\nadd_tab_button|token_menu|Growtoken Items|interface/large/btn_shop2.rttex||0|2|0|0||||-1|-1|||0|\nadd_button|5seed|`oSmall Seed Pack``|interface/large/store_buttons/store_buttons.rttex|`2You Get:`` 1 Small Seed Pack.<CR><CR>`5Description:`` Contains one Small Seed Pack. Open it for `$5`` randomly chosen seeds, including 1 rare seed! Who knows what you'll get?!|1|4|100|0|||-1|-1||-1|-1||1||||||0|\nadd_button|ssp_10_pack|`oSmall Seed Pack Collection``|interface/large/store_buttons/store_buttons18.rttex|`2You Get:`` 10 Small Seed Packs.<CR><CR>`5Description:`` Open each one for `$5`` randomly chosen seeds apiece, including 1 rare seed per pack! Who knows what you'll get?!|0|4|1000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|rare_seed|`oRare Seed Pack``|interface/large/store_buttons/store_buttons.rttex|`2You Get:`` 5 Randomly Chosen Rare Seeds.<CR><CR>`5Description:`` Expect some wondrous crops with these!|1|7|1000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|grow_spray|`o5-pack of Grow Spray Fertilizer``|interface/large/store_buttons/store_buttons.rttex|`2You Get:`` 5 Grow Spray Fertilizers.<CR><CR>`5Description:`` Why wait?!  Treat yourself to a `$5-pack`` of amazing `wGrow Spray Fertilizer`` by GrowTech Corp.  Each bottle instantly ages a tree by `$1 hour``.|0|6|400|0|||-1|-1||-1|-1||1||||||0|\nadd_button|deluxe_grow_spray|`oDeluxe Grow Spray``|interface/large/store_buttons/store_buttons11.rttex|`2You Get:`` 1 Deluxe Grow Spray.<CR><CR>`5Description:`` GrowTech's new `$Deluxe`` `wGrow Spray`` instantly ages a tree by `$24 hours`` per bottle! That's somewhere around 25 times as much as regular Grow Spray!|0|2|2000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|bountiful_seed_pack|`oBountiful Seed Pack``|interface/large/store_buttons/store_buttons28.rttex|`2You Get:`` 1 Bountiful Seed Pack.<CR><CR>`5Description:`` Contains `$5`` randomly chosen bountiful seeds, including 1 rare seed! Who knows what you'll get?!|0|4|1000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|fishin_pack|`oFishin' Pack``|interface/large/store_buttons/store_buttons14.rttex|`2You Get:`` 1 Fishing Rod, 5 Wiggly Worms, 1 Hand Drill, 1 Nuclear Detonator,  1 `#Rare Tackle Box``, 10 Fish Tanks and 1 `#Rare Fish Tank Port`` .<CR><CR>`5Description:`` Relax and sit by the shore... this pack includes a Fishing Rod, Wiggly Worms for bait, Hand Drill, Nuclear Detonator, and a `#Rare`` Tackle Box which provides you with more free bait every two days, Fish Tanks, and a `#Rare`` Fish Tank Port to put the fish you catch into your fish tank!|0|0|10000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|guild_name_changer|`oGuild Name Changer``|interface/large/store_buttons/store_buttons23.rttex|`2You Get:`` 1 Guild Name Changer.<CR><CR>`5Description:`` Fancy a change? Bored of your guild name or made a mistake when creating it? Fear not, you can use up one of these to change your `2Guild's name``! The usual name checks will be initiated to check if your new guild name is valid. `4Only usable by the guild leader!``|0|6|100000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|geiger|`oGeiger Counter``|interface/large/store_buttons/store_buttons12.rttex|`2You Get:`` 1 Geiger Counter.<CR><CR>`5Description:`` With this fantabulous device, you can detect radiation around you. It bleeps red, then yellow, then green as you get closer to the source. Who knows what you might find? `4Not available any other way!``|0|1|25000|0|||-1|-1||-1|-1||1||||||0|\nadd_button|guild_chest_pack|`oGuild Chest Pack``|interface/large/store_buttons/store_buttons19.rttex|`2You Get:`` 10 Guild Chests.<CR><CR>`5Description:`` A 10-pack of Guild Chests! Loaded with guildy goodness - pop a chest open for a surprise item!|0|4|20000|0|||-1|-1||-1|-1||1||||||0|"));
						ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet);
						delete p.data;
					}
					if (cch == "action|buy\nitem|itemomonth\n") {
						if (((PlayerInfo*)(peer->data))->gem > 349999)
						{

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 350000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							bool success = true;
							saveItem(11006, 1, peer, true);
							savejson(peer);
							saveinventorybuild(peer, true);
							Player::PlayAudio(peer, "audio/piano_nice.wav", 0);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "You've purchased `o1 Soul Scythe `wfor `$350000 `wGems.\n\n`5Received: ``1 Soul Scythe"));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else {
							Player::PlayAudio(peer, "audio/bleep_fail.wav", 0);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "You can't afford `oSoul Scythe``!  You're `$gems are short."));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (cch == "action|buy\nitem|world_lock\n") {
						if (((PlayerInfo*)(peer->data))->gem > 1999)
						{

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 2000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							bool success = true;
							saveItem(242, 1, peer, true);
							savejson(peer);
							saveinventorybuild(peer, true);
							Player::PlayAudio(peer, "audio/piano_nice.wav", 0);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "You've purchased `o1 World Lock `wfor `$2000 `wGems.\n\n`5Received: ``1 World Lock"));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else {
							Player::PlayAudio(peer, "audio/bleep_fail.wav", 0);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "You can't afford `oWorld Lock``!  You're `$gems are short."));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}
					if (cch == "action|buy\nitem|world_lock_10_pack\n") {
						if (((PlayerInfo*)(peer->data))->gem > 9999)
						{

							((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 10000;
							GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
							ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packetsa);

							bool success = true;
							saveItem(242, 10, peer, true);
							savejson(peer);
							saveinventorybuild(peer, true);
							Player::PlayAudio(peer, "audio/piano_nice.wav", 0);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "You've purchased `o10 World Locks `wfor `$10000 `wGems.\n\n`5Received: ``10 World Locks"));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						else {
							Player::PlayAudio(peer, "audio/bleep_fail.wav", 0);
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnStorePurchaseResult"), "You can't afford `o10 World Locks``!  You're `$gems are short."));
							ENetPacket* packet = enet_packet_create(p.data, p.len, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
					}

					if (cch.find("action|info") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						int id = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") id = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}
						if (id == -1 || count == -1) continue;
						if (itemDefs.size() < id || id < 0) continue;
						string properties = "\nadd_smalltext|";
						ItemDefinition itemDef = getItemDef(id);
						if (itemDef.properties & Property_MultiFacing) properties += "<CR>`1This item can be placed in two directions, depending on the direction you're facing.`` ";
						if (itemDef.properties & Property_Untradable) properties += "<CR>`1This item cannot be dropped or traded.`` ";
						if (itemDef.properties & Property_Wrenchable) properties += "<CR>`1This item has special properties you can adjust with the Wrench.`` ";
						if (itemDef.properties & Property_NoSeed) properties += "<CR>`1This item never drops any seeds.`` ";
						if (itemDef.properties & Property_Permanent) properties += "<CR>`1This item can't be destroyed - smashing it will return it to your backpack if you have room!`` ";
						if (properties != "\nadd_smalltext|") properties += "|left|";
						else properties = "";
						packet::dialog(peer, "set_default_color|`o\n\nadd_label_with_icon|big|`w" + itemDefs.at(id).name + "``|left|" + std::to_string(id) + "|\n\nadd_spacer|small|\nadd_smalltext|" + itemDefs.at(id).description + "|left|\nadd_spacer|small|\nadd_smalltext|`oRarity:`w " + to_string(itemDefs.at(id).rarity) + "|left|" + properties + "\nadd_quick_exit|\nend_dialog|item_info|OK||");
					}
					if (cch.find("action|dialog_return") == 0)
					{
						std::stringstream ss(cch);
						std::string to;
						string btn = "";
						string dropitemcount = "";
						bool isDropDialog = false;
						bool isRegisterDialog = false;
						string username = "";
						string password = "";
						string passwordverify = "";
						string email = "";
						string discord = "";
						string AAPcode = "";
						string AAPcodes = "";
						string haveSuperSupporterState = "";
						string haveBluename = "";
						string haveDuctTapeState = "";
						string haveCursedState = "";
						string haveZombieState = "";
						string editDisplayName = "";
						string editGems = "";
						string editSkin = "";
						string editUserID = "";
						string editPassword = "";
						string UserDC = "0";
						string editAAP = "";
						string timeUser = "0";
						string userBan = "0";
						string userMute = "0";
						string userCurse = "0";
						string fastPunch = "";
						string personal_note = "";
						string signText = "";
						string password_developerOP = "";
						string purplecape;
						string purpleportal;
						string purpleelectrical;
						string purplenight;
						string blackcape;
						string blackportal;
						string blackelectrical;
						string blacknight;
						string checkbox_public;
						string Open_To_Public = "";
						bool isDeveloperOP = false;
						bool isSignDialog = false;
						bool isPunishmentDialog = false;
						bool isEditUserDialog = false;
						bool aapcreate = false;
						bool aaprequest = false;
						bool notebook = false;
						bool isStoreDialog = false;
						bool isContinueBuy = false;
						bool isRiftCape = false;
						bool isLockDialog = false;
						bool gateway_apply = false;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 2) {
								if (infoDat[0] == "buttonClicked") btn = infoDat[1];
								if (infoDat[0] == "dialog_name" && infoDat[1] == "register")
								{
									isRegisterDialog = true;
								}
								if (isRegisterDialog) {
									if (infoDat[0] == "username") username = infoDat[1];
									if (infoDat[0] == "password") password = infoDat[1];
									if (infoDat[0] == "passwordverify") passwordverify = infoDat[1];
									if (infoDat[0] == "email") email = infoDat[1];
									if (infoDat[0] == "discord") discord = infoDat[1];
								}
								
								if (infoDat[0] == "dialog_name" && infoDat[1] == "dropdialog")
								{
									isDropDialog = true;
								}
								if (isDropDialog) {
									if (infoDat[0] == "dropitemcount") dropitemcount = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "aaprequest")
								{
									aaprequest = true;
								}
								if (aaprequest) {
									if (infoDat[0] == "AAPcode") AAPcode = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "aapcreate")
								{
									aapcreate = true;
								}
								if (aapcreate) {
									if (infoDat[0] == "AAPcodes") AAPcodes = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "punishUser_" + to_string(((PlayerInfo*)(peer->data))->lastUserID)) {
									isPunishmentDialog = true;
								}
								if (isPunishmentDialog) {
									if (infoDat[0] == "timeUser") timeUser = infoDat[1];
									if (infoDat[0] == "banUser") userBan = infoDat[1];
									if (infoDat[0] == "muteUser") userMute = infoDat[1];
									if (infoDat[0] == "curseUser") userCurse = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "editUser_" + to_string(((PlayerInfo*)(peer->data))->lastUserID)) {
									isEditUserDialog = true;
								}
								if (isEditUserDialog) {
									//Misc
									if (infoDat[0] == "editAAP") editAAP = infoDat[1];
									if (infoDat[0] == "editGems") editGems = infoDat[1];
									if (infoDat[0] == "editSkin") editSkin = infoDat[1];
									if (infoDat[0] == "editDisplayName") editDisplayName = infoDat[1];
									if (infoDat[0] == "editUserID") editUserID = infoDat[1];
									if (infoDat[0] == "editPassword") editPassword = infoDat[1];

									//State
									if (infoDat[0] == "haveBluename") haveBluename = infoDat[1];
									if (infoDat[0] == "fastPunch") fastPunch = infoDat[1];
									if (infoDat[0] == "haveSuperSupporterState") haveSuperSupporterState = infoDat[1];
									if (infoDat[0] == "haveDuctTapeState") haveDuctTapeState = infoDat[1];
									if (infoDat[0] == "haveCursedState") haveCursedState = infoDat[1];
									if (infoDat[0] == "haveZombieState") haveZombieState = infoDat[1];
									if (infoDat[0] == "UserDisconnect") UserDC = infoDat[1];


								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "notebook_edit")
								{
									notebook = true;
								}
								if (notebook) {
									if (infoDat[0] == "personal_note") personal_note = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "signok")
								{
									isSignDialog = true;
								}
								if (isSignDialog) {
									if (infoDat[0] == "signText") signText = infoDat[1];
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "store_run")
								{
									isStoreDialog = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "continue_buy_" + ((PlayerInfo*)(peer->data))->store_itemID) {
									isContinueBuy = true;
								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "developerOP" && ((PlayerInfo*)(peer->data))->adminLevel == 5) {
									isDeveloperOP = true;
								}
								if (isDeveloperOP) {
									if (infoDat[0] == "password_developerOP") password_developerOP = infoDat[1];

								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "riftcape_edit")
								{
									isRiftCape = true;
								}
								if (isRiftCape) {
									//Purple
									 //Jgn di hapus
									if (infoDat[0] == "purplecape") purplecape = infoDat[1];
									if (infoDat[0] == "purpleportal") purpleportal = infoDat[1];
									if (infoDat[0] == "purpleelectrical") purpleelectrical = infoDat[1];
									if (infoDat[0] == "purplenight") purplenight = infoDat[1];

									//black

									if (infoDat[0] == "blackcape") blackcape = infoDat[1];
									if (infoDat[0] == "blackportal") blackportal = infoDat[1];
									if (infoDat[0] == "blackelectrical") blackelectrical = infoDat[1];
									if (infoDat[0] == "blacknight") blacknight = infoDat[1];

								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "lock_edit" && ((PlayerInfo*)(peer->data))->rawName == world->owner) {
									isLockDialog = true;
								}
								if (isLockDialog) {
									if (infoDat[0] == "checkbox_public") checkbox_public = infoDat[1];

								}
								if (infoDat[0] == "dialog_name" && infoDat[1] == "gateway_edit") {
									gateway_apply = true;
								}
								if (gateway_apply) {
									if (infoDat[0] == "checkbox_public") Open_To_Public = infoDat[1];
								}
							}
						}
						if (gateway_apply) {
							if (Open_To_Public != "0" && Open_To_Public != "1") break;
							if (isWorldOwner(peer, world) || ((PlayerInfo*)(peer->data))->adminLevel == 5) {
								world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].opened = Open_To_Public == "0" ? 0 : 1;
								updateEntrance(peer, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].foreground, ((PlayerInfo*)(peer->data))->embed_tileX, ((PlayerInfo*)(peer->data))->embed_tileY, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].opened, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].background, true);
								break;
							}
						}
						if (isLockDialog) {
							if (checkbox_public == "1") {
								world->isPublic = true;
								sendTileData(peer, ((PlayerInfo*)(peer->data))->embed_tileX, ((PlayerInfo*)(peer->data))->embed_tileY, 0x10, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].foreground, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].background, lockTileDatas(0x20, atoi(((PlayerInfo*)(peer->data))->userID.c_str()), world->accessed.size(), world->accessed, true, 100));
							}
							else {
								world->isPublic = false;
								sendTileData(peer, ((PlayerInfo*)(peer->data))->embed_tileX, ((PlayerInfo*)(peer->data))->embed_tileY, 0x10, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].foreground, world->items[((PlayerInfo*)(peer->data))->embed_tileX + (((PlayerInfo*)(peer->data))->embed_tileY * world->width)].background, lockTileDatas(0x20, atoi(((PlayerInfo*)(peer->data))->userID.c_str()), world->accessed.size(), world->accessed, false, 100));
							}
						}
						if (isRiftCape) {
							if (purplecape == "1") {
								OnRiftApply(peer, 3000, 2402849791, 723421695, 2402849791, 1059267327, 30, 6);
							}
							if (purpleportal == "1") {
								OnRiftApply(peer, 2555, 2402849791, 723421695, 2402849791, 1059267327, 30, 6);
							}
							if (purpleelectrical == "1") {
								OnRiftApply(peer, 2888, 2402849791, 723421695, 2402849791, 1059267327, 30, 6);
							}
							if (purplenight == "1") {
								OnRiftApply(peer, 2777, 2402849791, 723421695, 2402849791, 1059267327, 30, 6);
							}
							//Black RiftCape
							if (blackcape == "1") {
								OnRiftApply(peer, 3000, 255, 231, 160, 1059267327, 30, 6);
							}
							if (blackportal == "1") {
								OnRiftApply(peer, 2555, 255, 231, 160, 1059267327, 30, 6);
							}
							if (blackelectrical == "1") {
								OnRiftApply(peer, 2888, 255, 231, 160, 1059267327, 30, 6);
							}
							if (blacknight == "1") {
								OnRiftApply(peer, 2777, 255, 231, 160, 1059267327, 30, 6);
							}

						}
						if (btn == "riftcape") {
							Player::OnDialogRequest(peer, "set_default_color|\nadd_label_with_icon|big|Edit Rift Cape|left|10424|"
								"\nadd_smalltext|`$This is where you can edit your 'Rift Cape'.|left|"
								"\nadd_smalltext|`#Purple Rift Cape|left|"
								"\nadd_checkbox|purplecape|`$Normal Rift Cape|0|"
								"\nadd_checkbox|purpleportal|`$Portal Rift Cape|0|"
								"\nadd_checkbox|purpleelectrical|`$Elecrtical Rift Cape|0|"
								"\nadd_checkbox|purplenight|`$Startfield Rift Cape|0|"
								"\nadd_smalltext|`bBlack Rift Cape|left|"
								"\nadd_checkbox|blackcape|`$Normal Rift Cape|0|"
								"\nadd_checkbox|blackportal|`$Portal Rift Cape|0|"
								"\nadd_checkbox|blackelectrical|`$Elecrtical Rift Cape|0|"
								"\nadd_checkbox|blacknight|`$Startfield Rift Cape|0|"
								"\nend_dialog|riftcape_edit|Close|`2Update|\n");
						}

						
						if (isStoreDialog)
						{
							if (btn == "storeItemMenu") {
								{
									((PlayerInfo*)(peer->data))->storeItemMenu =
										"set_default_color|`o"
										"\nadd_label_with_icon|big|`wGrowtopia Store: `2items that can be purchased|left|242|"
										"\nadd_spacer|small|"
										"\nadd_label_with_icon|small|`9Lock items|left|242|"
										"\nadd_spacer|small|"
										"\nadd_button_with_icon|buy_WL|`$World Lock``|frame|242|2000|\n"
										"\nadd_button_with_icon|buy_DL|`$Diamond Lock``|frame|1796|200000|\n"
										"\nadd_button_with_icon|buy_EL|`$Emerald Lock``|frame|2408|300000|\n"
										"\nadd_button_with_icon|buy_RL|`$Ruby Lock``|frame|4428|300000|\n"
										"\nadd_button_with_icon|buy_RBL|`$Robotic Lock``|frame|2950|300000|\n"
										"\nadd_button_with_icon|buy_BGL|`$Blue Gem Lock``|frame|7188|300000|\n"

										"\nadd_button_with_icon||END_LIST|noflags|0|0|"
										"\nadd_spacer|small|"
										"\nadd_label_with_icon|small|`9Legendary Items|left|1790|"
										"\nadd_spacer|small|"
										"\nadd_button_with_icon|buy_lgWING|`$Legendary Wings``|staticPurpleFrame|1784|150000|\n"
										"\nadd_button_with_icon|buy_lgDRAG|`$Dragon of Legend``|staticPurpleFrame|1782|150000|\n"
										"\nadd_button_with_icon|buy_lgBOT|`$LegendBot-009``|staticPurpleFrame|1780|150000|\n"

										"\nadd_button_with_icon||END_LIST|noflags|0|0|"
										"\nend_dialog|store_run||"
										"\nadd_quick_exit|";
								}
								Player::OnDialogRequest(peer, ((PlayerInfo*)(peer->data))->storeItemMenu);
							}
							if (btn == "storeEffectMenu")
							{
								//coming soon
							}
						}
						//Store

						{ //StoreItemMenu_Buy_Items_Confirm
							if (btn == "buy_WL")
								if (((PlayerInfo*)(peer->data))->gem > 1999)
								{

									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `5Purchased World Lock"));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;

									((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 2000;
									GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
									ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packetsa);

									delete psa.data;

									saveItem(242, 1, peer, true);
									savejson(peer);
									saveinventorybuild(peer, true);


									string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
									BYTE* data = new BYTE[5 + text.length()];
									BYTE zero = 0;
									int type = 3;
									memcpy(data, &type, 4);
									memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
									memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

									ENetPacket* packetsou = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(peer, 0, packetsou);

								}
								else
								{
									GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
									ENetPacket* packet = enet_packet_create(p.data,
										p.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet);
									delete p.data;
								}
						}
						if (btn == "buy_DL")
						{
							if (((PlayerInfo*)(peer->data))->gem > 199999)
							{

								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnTextOverlay"), "`wSuccessfully `5Purchased Diamond Lock"));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;

								((PlayerInfo*)(peer->data))->gem = ((PlayerInfo*)(peer->data))->gem - 200000;
								GamePacket psa = packetEnd(appendInt(appendString(createPacket(), "OnSetBux"), ((PlayerInfo*)(peer->data))->gem));
								ENetPacket* packetsa = enet_packet_create(psa.data, psa.len, ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packetsa);

								delete psa.data;

								saveItem(1796, 1, peer, true);
								savejson(peer);
								saveinventorybuild(peer, true);


								string text = "action|play_sfx\nfile|audio/achievement.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length()); // change memcpy here
								memcpy(data + 4 + text.length(), &zero, 1); // change memcpy here, revert to 4

								ENetPacket* packetsou = enet_packet_create(data,
									5 + text.length(),
									ENET_PACKET_FLAG_RELIABLE);

								enet_peer_send(peer, 0, packetsou);

							}
							else
							{
								GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`4TRANSACTION ABORTED! - `wNot enough gems."));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet);
								delete p.data;
							}
						}
						if (btn == "buy_EL")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buy_RL")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buy_RBL")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buy_BGL")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buy_lgWING")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "buy_lgDRAG")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						if (btn == "showoffline")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							string onlinelist = "";
							string offlinelist = "";
							string offname = "";
							int onlinecount = 0;
							int totalcount = static_cast<PlayerInfo*>(peer->data)->friendinfo.size();
							vector<string> offliness = static_cast<PlayerInfo*>(peer->data)->friendinfo;
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = static_cast<PlayerInfo*>(currentPeer->data)->rawName;
								if (find(static_cast<PlayerInfo*>(peer->data)->friendinfo.begin(), static_cast<PlayerInfo*>(peer->data)->friendinfo.end(), name) != static_cast<PlayerInfo*>(peer->data)->friendinfo.end())
								{
									onlinelist += "\nadd_button|onlinefrns_" + static_cast<PlayerInfo*>(currentPeer->data)->rawName + "|`2ONLINE: `o" + static_cast<PlayerInfo*>(currentPeer->data)->displayName + "``|0|0|";
									onlinecount++;
									offliness.erase(std::remove(offliness.begin(), offliness.end(), name), offliness.end());
								}
							}
							for (std::vector<string>::const_iterator i = offliness.begin(); i != offliness.end(); ++i)
							{
								offname = *i;
								offlinelist += "\nadd_button|offlinefrns_" + offname + "|`4OFFLINE: `o" + offname + "``|0|0|";
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_spacer|small|" + offlinelist + "\nadd_spacer|small|\n\nadd_button|frnoption|`oFriend Options``|0|0|\nadd_button|backonlinelist|Back``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "removecon")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							if (static_cast<PlayerInfo*>(peer->data)->haveGrowId == false)
							{
								continue;
							}
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (static_cast<PlayerInfo*>(currentPeer->data)->rawName == static_cast<PlayerInfo*>(peer->data)->lastFrn)
								{
									static_cast<PlayerInfo*>(peer->data)->friendinfo.erase(std::remove(static_cast<PlayerInfo*>(peer->data)->friendinfo.begin(), static_cast<PlayerInfo*>(peer->data)->friendinfo.end(), static_cast<PlayerInfo*>(peer->data)->lastFrn), static_cast<PlayerInfo*>(peer->data)->friendinfo.end());
									static_cast<PlayerInfo*>(currentPeer->data)->friendinfo.erase(std::remove(static_cast<PlayerInfo*>(currentPeer->data)->friendinfo.begin(), static_cast<PlayerInfo*>(currentPeer->data)->friendinfo.end(), static_cast<PlayerInfo*>(peer->data)->rawName), static_cast<PlayerInfo*>(currentPeer->data)->friendinfo.end());

									//for me

									ifstream fg("players/" + static_cast<PlayerInfo*>(peer->data)->rawName + ".json");
									json j;
									fg >> j;
									fg.close();

									j["friends"] = static_cast<PlayerInfo*>(peer->data)->friendinfo;

									ofstream fs("players/" + static_cast<PlayerInfo*>(peer->data)->rawName + ".json");
									fs << j;
									fs.close();

									// for another player

									ifstream fgg("players/" + PlayerDB::getProperName(static_cast<PlayerInfo*>(currentPeer->data)->rawName) + ".json");
									json jj;
									fgg >> jj;
									fgg.close();

									jj["friends"] = static_cast<PlayerInfo*>(currentPeer->data)->friendinfo;

									ofstream fss("players/" + PlayerDB::getProperName(static_cast<PlayerInfo*>(currentPeer->data)->rawName) + ".json");
									fss << jj;
									fss.close();

									Player::OnConsoleMessage(currentPeer, "`3FRIEND ALERT: `2" + static_cast<PlayerInfo*>(peer->data)->displayName + " `ohas removed you as a friend.");
									GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Friend removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`oOk, you are no longer friends with `o" + static_cast<PlayerInfo*>(peer->data)->lastFrnName + ".``|\n\nadd_spacer|small|\nadd_button||`oOK``|0|0|\nadd_quick_exit|"));
									ENetPacket* packet2 = enet_packet_create(p2.data,
										p2.len,
										ENET_PACKET_FLAG_RELIABLE);
									enet_peer_send(peer, 0, packet2);
									delete p2.data;
									break;
								}
							}
						}
						if (btn == "removeconoff")
						{
							/*if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							if (static_cast<PlayerInfo*>(peer->data)->haveGrowId == false)
							{
								continue;
							}
							static_cast<PlayerInfo*>(peer->data)->friendinfo.erase(std::remove(static_cast<PlayerInfo*>(peer->data)->friendinfo.begin(), static_cast<PlayerInfo*>(peer->data)->friendinfo.end(), static_cast<PlayerInfo*>(peer->data)->lastFrn), static_cast<PlayerInfo*>(peer->data)->friendinfo.end());


							MYSQL_ROW row;
							if (conn == nullptr)
							{
								cout << "null" << endl;
								continue;
							}
							if (conn != nullptr)
							{
								stringstream sse;
								sse << "SELECT friends FROM PlayerDatabase WHERE username = '" + static_cast<PlayerInfo*>(peer->data)->lastFrn + "'";
								auto query = sse.str();
								auto q = query.c_str();
								if (mysql_query(conn, q))
								{
											string ers = mysql_error(conn); if (ers.find("Lost connection") != string::npos) ConnectToDatabase();
									cout << mysql_error(conn) << endl;


									enet_peer_disconnect_now(peer, 0);
									continue;
								}
								string Friends;
								res = mysql_store_result(conn);
								while (row = mysql_fetch_row(res))
								{
									Friends = row[17];
								}

								stringstream ss(Friends);
								vector<string> result;
								while (ss.good())
								{
									string substr;
									getline(ss, substr, ',');
									if (substr.size() == 0) continue;
									result.push_back(substr);
								}
								result.erase(std::remove(result.begin(), result.end(), static_cast<PlayerInfo*>(peer->data)->rawName), result.end());
								string friends_string = "";
								for (int i = 0; i < result.size(); i++)
								{
									friends_string += result[i] + ",";
								}
								auto qstate = 0;
								if (conn == nullptr)
								{
									cout << "conn was nullptr" << endl;
									continue;
								}
								if (conn != nullptr)
								{
									stringstream sss;
									sss << "UPDATE PlayerDatabase SET friends = '" + friends_string + "' WHERE username = '" + static_cast<PlayerInfo*>(peer->data)->lastFrn + "'";
									auto queryy = sss.str();
									const auto qq = queryy.c_str();
									if (mysql_query(conn, qq))
									{
												string ers = mysql_error(conn); if (ers.find("Lost connection") != string::npos) ConnectToDatabase();
										cout << mysql_error(conn) << endl;


										enet_peer_disconnect_now(peer, 0);
										continue;
									}
								}
							}
							else
							{
								continue;
							}


							string friends_string = "";
							for (int i = 0; i < static_cast<PlayerInfo*>(peer->data)->friendinfo.size(); i++)
							{
								friends_string += static_cast<PlayerInfo*>(peer->data)->friendinfo[i] + ",";
							}

							auto qstate = 0;
							if (conn == nullptr)
							{
								cout << "conn was nullptr" << endl;
								continue;
							}
							if (conn != nullptr)
							{
								stringstream ss;
								ss << "UPDATE PlayerDatabase SET friends = '" + friends_string + "' WHERE username = '" + PlayerDB::getProperName(static_cast<PlayerInfo*>(peer->data)->rawName) + "'";
								auto query = ss.str();
								const auto q = query.c_str();
								if (mysql_query(conn, q))
								{
											string ers = mysql_error(conn); if (ers.find("Lost connection") != string::npos) ConnectToDatabase();
									cout << mysql_error(conn) << endl;


									enet_peer_disconnect_now(peer, 0);
									continue;
								}
							}*/

							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`4Friend removed``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`oOk, you are no longer friends with `o" + static_cast<PlayerInfo*>(peer->data)->lastFrn + ".``|\n\nadd_spacer|small|\nadd_button||`oOK``|0|0|\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn.substr(0, 11) == "onlinefrns_")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (static_cast<PlayerInfo*>(currentPeer->data)->rawName == btn.substr(11, cch.length() - 11 - 1))
								{
									static_cast<PlayerInfo*>(peer->data)->lastFrnWorld = static_cast<PlayerInfo*>(currentPeer->data)->currentWorld;
									static_cast<PlayerInfo*>(peer->data)->lastFrnName = static_cast<PlayerInfo*>(currentPeer->data)->tankIDName;
									static_cast<PlayerInfo*>(peer->data)->lastFrn = static_cast<PlayerInfo*>(currentPeer->data)->rawName;
								}
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + static_cast<PlayerInfo*>(peer->data)->lastFrnName + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + static_cast<PlayerInfo*>(peer->data)->lastFrnName + " is `2online `onow in the world `5" + static_cast<PlayerInfo*>(peer->data)->lastFrnWorld + "`o.|\n\nadd_spacer|small|\nadd_button|frnwarpbutton|`oWarp to `5" + static_cast<PlayerInfo*>(peer->data)->lastFrnWorld + "``|0|0|\nadd_button|msgbutton|`5Send message``|0|0|\n\nadd_spacer|small|\nadd_button|removecon|`oRemove as friend``|0|0|\nadd_button|backonlinelist|`oBack``|0|0|\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "frnwarpbutton")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}

						}
						if (btn == "msgbutton")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`5Message to `o" + static_cast<PlayerInfo*>(peer->data)->lastFrnName + "|left|660|\nadd_spacer|small|\nadd_text_input|msgtext|||50|\nend_dialog|msgdia|Cancel|`5Send``| \nadd_spacer|big|\nadd_button|backonlinelist|`oBack``|0|0|\nadd_quick_exit|\n"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn.substr(0, 12) == "offlinefrns_")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							static_cast<PlayerInfo*>(peer->data)->lastFrn = btn.substr(12, cch.length() - 12 - 1);
							GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`w" + static_cast<PlayerInfo*>(peer->data)->lastFrn + "``|left|1366|\n\nadd_spacer|small|\nadd_textbox|`o" + static_cast<PlayerInfo*>(peer->data)->lastFrn + " is `4offline`o.``|\nadd_spacer|small|\nadd_button|removeconoff|`oRemove as friend``|0|0|\nadd_button|showoffline|`oBack``|0|0|\nadd_quick_exit|"));
							ENetPacket* packet2 = enet_packet_create(p2.data,
								p2.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet2);
							delete p2.data;
						}
						if (btn == "backsocialportal")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							if (static_cast<PlayerInfo*>(peer->data)->joinguild == true)
							{
								Player::OnDialogRequest(peer, "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|showguild|Show Guild Members``|0|0|\nend_dialog||OK||\nadd_quick_exit|");
							}
							else
							{
								Player::OnDialogRequest(peer, "set_default_color|`w\n\nadd_label_with_icon|big|Social Portal``|left|1366|\n\nadd_spacer|small|\nadd_button|backonlinelist|Show Friends``|0|0|\nadd_button|createguildinfo|Create Guild``|0|0|\nend_dialog||OK||\nadd_quick_exit|");
							}
						}
						if (btn == "backonlinelist")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							string onlinefrnlist = "";
							int onlinecount = 0;
							int totalcount = static_cast<PlayerInfo*>(peer->data)->friendinfo.size();
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								string name = static_cast<PlayerInfo*>(currentPeer->data)->rawName;
								if (find(static_cast<PlayerInfo*>(peer->data)->friendinfo.begin(), static_cast<PlayerInfo*>(peer->data)->friendinfo.end(), name) != static_cast<PlayerInfo*>(peer->data)->friendinfo.end())
								{
									onlinefrnlist += "\nadd_button|onlinefrns_" + static_cast<PlayerInfo*>(currentPeer->data)->rawName + "|`2ONLINE: `o" + static_cast<PlayerInfo*>(currentPeer->data)->tankIDName + "``|0|0|";
									onlinecount++;
								}
							}
							if (totalcount == 0)
							{
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_label|small|`1To add friends in `4Growtopia `1Click on someone's name and click add as a friend!`o.``|left|4|\n\nadd_spacer|small|\nadd_button||`5Close``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else if (onlinecount == 0)
							{
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|\nadd_label|small|`oNone of your friends are currently online.``|left|4|\n\nadd_spacer|small|\nadd_button|showoffline|`5Show offline``|0|0|\nadd_button||`5Close``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
							else
							{
								GamePacket p2 = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`o" + std::to_string(onlinecount) + " of " + std::to_string(totalcount) + " `wFriends Online``|left|1366|\n\nadd_spacer|small|\nadd_button|chc0|`wClose``|0|0|" + onlinefrnlist + "\n\nadd_spacer|small|\nadd_button|showoffline|`5Show offline``|0|0|\nadd_button||`oClose``|0|0|\nadd_quick_exit|"));
								ENetPacket* packet2 = enet_packet_create(p2.data,
									p2.len,
									ENET_PACKET_FLAG_RELIABLE);
								enet_peer_send(peer, 0, packet2);
								delete p2.data;
							}
						}
						if (btn == "addfriendrnbutton")
						{
							if (static_cast<PlayerInfo*>(peer->data)->currentWorld == "EXIT")
							{
								continue;
							}
							if (static_cast<PlayerInfo*>(peer->data)->haveGrowId == true)
							{
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (static_cast<PlayerInfo*>(currentPeer->data)->rawName == static_cast<PlayerInfo*>(peer->data)->lastInfo)
									{
										// if last wrench
										if (static_cast<PlayerInfo*>(peer->data)->lastfriend == static_cast<PlayerInfo*>(currentPeer->data)->rawName)
										{
											// last  h friend
											static_cast<PlayerInfo*>(peer->data)->friendinfo.push_back(static_cast<PlayerInfo*>(currentPeer->data)->rawName); //add
											static_cast<PlayerInfo*>(currentPeer->data)->friendinfo.push_back(static_cast<PlayerInfo*>(peer->data)->rawName);

											//for me

											ifstream fg("players/" + static_cast<PlayerInfo*>(peer->data)->rawName + ".json");
											json j;
											fg >> j;
											fg.close();

											j["friends"] = static_cast<PlayerInfo*>(peer->data)->friendinfo;

											ofstream fs("players/" + static_cast<PlayerInfo*>(peer->data)->rawName + ".json");
											fs << j;
											fs.close();

											// for another player

											ifstream fgg("players/" + PlayerDB::getProperName(static_cast<PlayerInfo*>(currentPeer->data)->rawName) + ".json");
											json jj;
											fgg >> jj;
											fgg.close();

											jj["friends"] = static_cast<PlayerInfo*>(currentPeer->data)->friendinfo;

											ofstream fss("players/" + PlayerDB::getProperName(static_cast<PlayerInfo*>(currentPeer->data)->rawName) + ".json");
											fss << jj;
											fss.close();


											string text = "action|play_sfx\nfile|audio/love_in.wav\ndelayMS|0\n";
											BYTE* data = new BYTE[5 + text.length()];
											BYTE zero = 0;
											int type = 3;
											memcpy(data, &type, 4);
											memcpy(data + 4, text.c_str(), text.length());
											memcpy(data + 4 + text.length(), &zero, 1);
											ENetPacket* packet2 = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet2);
											enet_peer_send(peer, 0, packet2);
											delete data;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ADDED: `oYou're now friends with `w" + static_cast<PlayerInfo*>(peer->data)->displayName + "`o!"));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											delete p.data;
											GamePacket p3 = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND ADDED: `oYou're now friends with `w" + static_cast<PlayerInfo*>(currentPeer->data)->displayName + "`o!"));
											ENetPacket* packet3 = enet_packet_create(p3.data,
												p3.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet3);
											delete p3.data;
										}
										else
										{
											GamePacket p4 = packetEnd(appendString(appendIntx(appendString(createPacket(), "OnTalkBubble"), static_cast<PlayerInfo*>(peer->data)->netID), "`5[`wFriend request sent to " + static_cast<PlayerInfo*>(currentPeer->data)->displayName + "`5]"));
											ENetPacket* packet4 = enet_packet_create(p4.data,
												p4.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(peer, 0, packet4);
											delete p4.data;
											string text = "action|play_sfx\nfile|audio/tip_start.wav\ndelayMS|0\n";
											BYTE* data = new BYTE[5 + text.length()];
											BYTE zero = 0;
											int type = 3;
											memcpy(data, &type, 4);
											memcpy(data + 4, text.c_str(), text.length());
											memcpy(data + 4 + text.length(), &zero, 1);
											ENetPacket* packet2 = enet_packet_create(data,
												5 + text.length(),
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet2);
											delete data;
											static_cast<PlayerInfo*>(currentPeer->data)->lastfriend = static_cast<PlayerInfo*>(peer->data)->rawName;
											GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`3FRIEND REQUEST: `oYou've received a `wfriend request `ofrom `w" + static_cast<PlayerInfo*>(peer->data)->displayName + "`o! To accept, click the `wwrench by his/her name `oand then choose `wAdd as friend`o."));
											ENetPacket* packet = enet_packet_create(p.data,
												p.len,
												ENET_PACKET_FLAG_RELIABLE);
											enet_peer_send(currentPeer, 0, packet);
											delete p.data;
										}
									}
								}
							}
							else
							{
								SendRegisterDialog(peer);
							}
						}
						if (btn == "buy_lgBOT")
						{
							GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnConsoleMessage"), "`r`2Coming Soon."));
							ENetPacket* packet = enet_packet_create(p.data,
								p.len,
								ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
							delete p.data;
						}
						/*if (btn == "buy_WL", "buy_DL", "buy_EL", "buy_RL", "buy_RBL", "buy_BGL", "buy_lgWING", "buy_lgDRAG", "buy_lgBOT") {
							if (((PlayerInfo*)(peer->data))->store_Confirm == true)
							{
								string status_gem;
								string cukup;
								if (((PlayerInfo*)(peer->data))->gem < atoi(((PlayerInfo*)(peer->data))->store_itemPrice.c_str()))
								{
									status_gem = "`4";
									cukup = "`4You don't have enough gems to buy this item";
								}
								else { status_gem = "`2"; cukup = "`2You have enough gems to buy this item"; } //ini bermaksud total gems lu sama dengan harga yang harus di bayar
								string storeConfirmItem =
									"set_default_color|`o"
									"\nadd_label_with_icon|big|`wGrowtopia Store: `2Buy "+ ((PlayerInfo*)(peer->data))->store_itemName+"|left|"+ ((PlayerInfo*)(peer->data))->store_itemID+"|"
									"\nadd_textbox|`wPlease confirm before purchasing this item|"
									"\nadd_spacer|small|"
									"\nadd_textbox|`oPlease check the item info below|"
									"\nadd_label_with_icon|small|`oName`w: `9"+ ((PlayerInfo*)(peer->data))->store_itemName +"|left|" + ((PlayerInfo*)(peer->data))->store_itemID + "|"
									"\nadd_label_with_icon|small|`oPrice`w: "+status_gem+ ((PlayerInfo*)(peer->data))->store_itemPrice +"|left|112|"
									"\nadd_label_with_icon|small|`oNOTE`w: "+cukup+"|left|1752|"
									"\nend_dialog|continue_buy_"+ ((PlayerInfo*)(peer->data))->store_itemID +"|CANCEL|"+status_gem+"BUY|\n";
								Player::OnDialogRequest(peer, storeConfirmItem);
								((PlayerInfo*)(peer->data))->store_Confirm = false;
							}
						}
					}

					{ //StoreEffectMenu_Buy_Effects_Confirm

					}
				}
				if (isContinueBuy) {
					bool ada = std::experimental::filesystem::exists(("playersStoreData\\" + ((PlayerInfo*)(peer->data))->rawName).c_str());
					if (ada) {
						Player::OnSetBux(peer, ((PlayerInfo*)(peer->data))->gem - atoi(((PlayerInfo*)(peer->data))->store_itemPrice.c_str()), 0);
						((PlayerInfo*)(peer->data))->gem -= atoi(((PlayerInfo*)(peer->data))->store_itemPrice.c_str());
						savejson(peer);
						saveItem(atoi(((PlayerInfo*)(peer->data))->store_itemID.c_str()), 1, peer, true);
						saveinventorybuild(peer, true);

						Player::OnConsoleMessage(peer, "Testing::" + to_string(((PlayerInfo*)(peer->data))->gem));
					}
					else {
						//Folder Invalid
						std::experimental::filesystem::create_directory(("playersStoreData\\" + ((PlayerInfo*)(peer->data))->rawName).c_str());

					}

				}*/
						if (isSignDialog)
						{
							if (((PlayerInfo*)(peer->data))->currentWorld != "EXIT")
							{
								string signContent = signText;
								int x = ((PlayerInfo*)(peer->data))->embed_tileX;
								int y = ((PlayerInfo*)(peer->data))->embed_tileY;
								if (signContent.length() < 128) {
									world->items[x + (y * world->width)].sign = signContent;
									int fg = world->items[x + (y * world->width)].foreground;
									int bg = world->items[x + (y * world->width)].background;
									ENetPeer* currentPeer;

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer)) {
											updateSign(currentPeer, fg, bg, x, y, signContent, world);
										}
									}
								}
							}
						}
						if (notebook) {
							string notebookDialog =
								"set_default_color|`o"
								"\nadd_label|big|`wNotebook|left|1752|"
								"\nadd_text_box_input|personal_note||" + personal_note + "|128|5|"
								"\nadd_spacer|small|"
								"\nadd_button|save|Save|noflags|0|0|"
								"\nadd_button|clear|Clear|noflags|0|0|"
								"\nadd_button|cancel|Cancel|noflags|0|0|"
								"\nend_dialog|notebook_edit||"
								"\nadd_quick_exit|"
								;
							if (btn == "save") {
								((PlayerInfo*)(peer->data))->personal_note = personal_note;
								Player::OnDialogRequest(peer, notebookDialog);
								saveOptions(peer);
								break;
							}
							else if (btn == "clear") {
								((PlayerInfo*)(peer->data))->personal_note = "";
								Player::OnDialogRequest(peer, notebookDialog);
								saveOptions(peer);
								break;
							}
							else {
								//Nothing
							}
						}
						if (btn == "notebook") {
							string notebookDialog =
								"set_default_color|`o"
								"\nadd_label|big|`wNotebook|left|0|"
								"\nadd_text_box_input|personal_note||" + ((PlayerInfo*)(peer->data))->personal_note + "|128|5|"
								"\nadd_spacer|small|"
								"\nadd_button|save|Save|noflags|0|0|"
								"\nadd_button|clear|Clear|noflags|0|0|"
								"\nadd_button|cancel|Cancel|noflags|0|0|"
								"\nend_dialog|notebook_edit||"
								"\nadd_quick_exit|"
								;
							Player::OnDialogRequest(peer, notebookDialog);
						}
						if (btn == "achi")
						{
							string buffs11;
							bool achi1 = std::experimental::filesystem::exists("achievements/wl/" + ((PlayerInfo*)(peer->data))->rawName + ".txt");
							if (achi1 == true)
							{
								buffs11 += "\nadd_achieve|This is my land (Classic) |Earned for using for a World lock|left|26|";
							}
							else
							{
								buffs11 += "\nadd_achieve|This is my land (Classic) |Not achieved!|left|125|";
							}

							Player::OnDialogRequest(peer, "set_default_color|\nadd_label_with_icon|small|`o" + ((PlayerInfo*)(peer->data))->rawName + " Achievements|left|982|\nadd_spacer|small|\nadd_textbox|" + buffs11 + "|\nadd_spacer|small|\nadd_button|gayno|`wContinue|noflags|0|0|\nend_dialog|gayno||");
						}
						if (btn.substr(0, 4) == "tool") {
							if (has_only_digits(btn.substr(4, btn.length() - 4)) == false) break;
							int Id = atoi(btn.substr(4, btn.length() - 4).c_str());
							std::ifstream iffff("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
							json jj;
							if (iffff.fail()) {
								std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
								if (!oo.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								json items;
								json jjall = json::array();
								json jj;
								jj["position"] = 1;
								jj["itemid"] = 18;
								jj["count"] = 1;
								jjall.push_back(jj);
								jj["position"] = 2;
								jj["itemid"] = 32;
								jj["count"] = 1;
								jjall.push_back(jj);
								for (int i = 2; i < 250; i++)
								{
									jj["position"] = i + 1;
									jj["itemid"] = 0;
									jj["count"] = 0;
									jjall.push_back(jj);
								}
								items["items"] = jjall;
								oo << items << std::endl;
								continue;
								iffff.close();
							}
							if (iffff.is_open()) {
							}
							iffff >> jj; //
							std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
							if (!oo.is_open()) {
								cout << GetLastError() << endl;
								_getch();
							}
							PlayerInventory inventory = ((PlayerInfo*)(peer->data))->inventory;

							for (int i = 0; i < inventory.inventorySize; i++)
							{
								int itemid = jj["items"][i]["itemid"];
								int quantity = jj["items"][i]["count"];
								if (itemid == 0 && quantity == 0)
								{
									jj["items"][i]["itemid"] = Id;
									jj["items"][i]["count"] = 200;
									break;
								}
							}
							oo << jj << std::endl;
							InventoryItem item;
							item.itemID = Id;
							item.itemCount = 200;
							((PlayerInfo*)(peer->data))->inventory.items.push_back(item);
							sendInventory(peer, ((PlayerInfo*)(peer->data))->inventory);
						}
						if (isDropDialog) {
							if (dropitemcount.size() > 3 || dropitemcount.size() <= 0)
							{
								continue;
							}
							int x;
							try {
								x = stoi(dropitemcount);
							}
							catch (std::invalid_argument& e) {
								Player::OnConsoleMessage(peer, "`^Item `@dropped `^successfully!");
								continue;
							}
							short int currentItemCount = 0;
							for (int i = 0; i < ((PlayerInfo*)(peer->data))->inventory.items.size(); i++)
							{
								if (((PlayerInfo*)(peer->data))->inventory.items.at(i).itemID == ((PlayerInfo*)(peer->data))->lastdropitem)
								{
									currentItemCount = (unsigned int)((PlayerInfo*)(peer->data))->inventory.items.at(i).itemCount;
								}
							}
							if (x <= 0) {
								Player::OnConsoleMessage(peer, "`^That too many or too less to drop!");
								continue;
							}
							else {
								bool iscontainseas = false;
								SearchInventoryItem(peer, ((PlayerInfo*)(peer->data))->lastdropitem, 1, iscontainseas);
								if (!iscontainseas)
								{
						
								}
								else {
									int xx = ((PlayerInfo*)(peer->data))->x + (32 * (((PlayerInfo*)(peer->data))->isRotatedLeft ? -1 : 1));
									int netid = -1;
									int yy = ((PlayerInfo*)(peer->data))->y;
									sendDrop(peer, netid, xx, yy, ((PlayerInfo*)(peer->data))->lastdropitem, x, 0, false); //pro1 sendDrop(peer, -1, item.x, item.y, item.id, item.count, 0, false);
									RemoveInventoryItem(((PlayerInfo*)(peer->data))->lastdropitem, x, peer);
									updateplayerset(peer, ((PlayerInfo*)(peer->data))->lastdropitem);
								}

							}
						}
						if (aapcreate) {
							string wrong;
							if (AAPcodes.size() < 5) {
								wrong = "\nadd_textbox|`4You must enter a minimum of 5 letter codes!|";
							}
							if (AAPcodes == "") {
								wrong = "\nadd_textbox|`4Code cannot be empty!|";
							}
							if (AAPcodes == "" || AAPcodes.size() < 5) {
								string AAPdialog = (
									"set_default_color|`o\n\nadd_label_with_icon|big|`wAdvanced Account Protection``|left|242|\n\nadd_spacer|small|" + wrong + "\nadd_smalltext|`wTo protect your account because if only the password would not be accurate because there could be a hacker who knows your password and takes your item, so this aap function to enhance security using a verification code and each log you must verify that you are the owner of this account by entering the code you have created before.|\nadd_textbox|`2You can use big or small word(A-z)/0-9/or symbols like @|\nadd_text_input|AAPcodes|Create Code:||5|\nend_dialog|aapcreate|Cancel|`2Activate|\n"
									);
								Player::OnDialogRequest(peer, AAPdialog);
							}
							else {
								Player::OnConsoleMessage(peer, "`2Successfully, Advanced Account Protection has been activated.");
								((PlayerInfo*)(peer->data))->AAP = AAPcodes;
								saveOptions(peer);
							}
						}
						if (btn == "aapactive") {
							string AAPdialog = (
								"set_default_color|`o\n\nadd_label_with_icon|big|`wAdvanced Account Protection``|left|242|\n\nadd_spacer|small|\nadd_smalltext|`wTo protect your account because if only the password would not be accurate because there could be a hacker who knows your password and takes your item, so this aap function to enhance security using a verification code and each log you must verify that you are the owner of this account by entering the code you have created before.|\nadd_textbox|`2You can use big or small word(A-z)/0-9/or symbols like @|\nadd_text_input|AAPcodes|Create Code:||5|\nend_dialog|aapcreate|Cancel|`2Activate|\n"
								);
							Player::OnDialogRequest(peer, AAPdialog);
						}

						if (isPunishmentDialog) {
							if (((PlayerInfo*)(peer->data))->adminLevel < 2) continue;
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
									if (timeUser.find_first_not_of("0123456789") != std::string::npos)
									{
										Player::OnConsoleMessage(peer, "`4Failed, invalid time (" + timeUser + ").");
										continue;
										break;
									}
									else if (timeUser == "0") {
										Player::OnConsoleMessage(peer, "`4Failed, invalid time (" + timeUser + ").");
										continue;
										break;
									}
									/*
									{
									int inputMinutes = 0;
									inputMinutes = atoi(timeUser.c_str());
									int days = inputMinutes / 1440;
									inputMinutes = inputMinutes % 1440;
									int hours = inputMinutes / 60;
									int mins = inputMinutes % 60;
									int seconds = inputMinutes % 1 * 60;

									//
									string d, h, m, s;
									string dd, hh, mm, ss;
									if (days == 1) {
										d = "`$" + to_string(days) + " `oday`` ";
										dd = "`w" + to_string(days) + " `wday`` ";
									}
									else if (days == 0) {
										d = "";
										dd = "";
									}
									else {
										d = "`$" + to_string(days) + " `odays`` ";
										dd = "`w" + to_string(days) + " `wdays`` ";
									}
									if (hours == 1) {
										h = "`$" + to_string(hours) + " `ohour`` ";
										hh = "`w" + to_string(hours) + " `whour`` ";
									}
									else if (hours == 0) {
										h = "";
										hh = "";
									}
									else {
										h = "`$" + to_string(hours) + " `ohours`` ";
										hh = "`w" + to_string(hours) + " `whours`` ";
									}
									if (mins == 1) {
										m = "`$" + to_string(mins) + " `omin`` ";
										mm = "`w" + to_string(mins) + " `wmin`` ";
									}
									else if (mins == 0) {
										m = "";
										mm = "";
									}
									else {
										m = "`$" + to_string(mins) + " `omins`` ";
										mm = "`w" + to_string(mins) + " `wmins`` ";
									}
									if (seconds == 1) {
										s = "`$" + to_string(seconds) + " `osecond``";
										ss = "`w" + to_string(seconds) + " `wsecond``";
									}
									else if (seconds == 0) {
										s = "";
										ss = "";
									}
									else {
										s = "`$" + to_string(seconds) + " `oseconds``";
										ss = "`w" + to_string(seconds) + " `wseconds``";
									}
									//
									string dhms = d + h + m + s;
									string ddhhmmss = dd + hh + mm + ss;
									}

									*/
									string dhms = OutputBanTime(calcBanDuration(atoi(timeUser.c_str())));
									string ddhhmmss = OutputBanTime(calcBanDuration(atoi(timeUser.c_str())));
									if (userBan == "1") {
										Player::OnConsoleMessage(currentPeer, "`oReality flickers as you begin to wake up! (`$Ban `omod added, `$" + dhms + " left)");
										Player::OnConsoleMessage(currentPeer, "`oWarning from `4SYSTEM`o: You've been `4BANNED `ofrom Growtopia for " + dhms + ".");
										Player::OnAddNotification(currentPeer, "`wWarning from `4SYSTEM`w: You've been `4BANNED `wfrom Growtopia for " + ddhhmmss + "", "audio/hub_open.wav", "interface/atomic_button.rttex");
										((PlayerInfo*)(currentPeer->data))->banned = true;
										((PlayerInfo*)(currentPeer->data))->bantape = true;
									}
									if (userMute == "1") {
										Player::OnConsoleMessage(currentPeer, "`oDuct tape has covered your mouth! (`$Duct Tape `omod added, `$" + dhms + " left)");
										Player::OnConsoleMessage(currentPeer, "`oWarning from `4SYSTEM`o: You've been `4duct-taped `ofor " + dhms + ".");
										Player::OnAddNotification(currentPeer, "`wWarning from `4SYSTEM`w: You've been `4duct-taped `wfor " + ddhhmmss + "", "audio/hub_open.wav", "interface/atomic_button.rttex");
										((PlayerInfo*)(currentPeer->data))->taped = true;
										((PlayerInfo*)(currentPeer->data))->isDuctaped = true;
									}
									if (userCurse == "1") {
										Player::OnConsoleMessage(currentPeer, "`oWarning from `4SYSTEM`o: You've been `4cursed `ofor " + dhms + ".");
										Player::OnAddNotification(currentPeer, "`wWarning from `4SYSTEM`w: You've been `4cursed `wfor " + ddhhmmss + "", "audio/hub_open.wav", "interface/atomic_button.rttex");
										((PlayerInfo*)(currentPeer->data))->cursed = true;
										((PlayerInfo*)(currentPeer->data))->isCursed = true;
									}
									savePunishment(currentPeer);
									savejson(currentPeer);
									saveOptions(currentPeer);
									sendState(currentPeer);
									sendClothes(currentPeer);
									if (userBan == "1") {

										autoBan(currentPeer, true, atoi(timeUser.c_str()));
									}
								}
							}
						}
						
						
					
						if (btn == "punishview_" + to_string(((PlayerInfo*)(peer->data))->lastUserID)) {
							if (((PlayerInfo*)(peer->data))->adminLevel < 2) continue;

							string status_ban = "0";
							string status_mute = "0";
							string status_curse = "0";
							//
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
									if (((PlayerInfo*)(currentPeer->data))->banned == true) {
										status_ban = "1";
									}
									if (((PlayerInfo*)(currentPeer->data))->taped == true) {
										status_mute = "1";
									}
									if (((PlayerInfo*)(currentPeer->data))->cursed == true) {
										status_curse = "1";
									}

									string punishOptions =
										"set_default_color|`o\nadd_label_with_icon|big|`oEditing " + ((PlayerInfo*)(currentPeer->data))->displayName + " `o(`##" + ((PlayerInfo*)(currentPeer->data))->userID + "`o)``|left|276|"
										"\nadd_spacer|small|"
										"\nadd_button||"
										"\nadd_label_with_icon|small|`wPunishment``|left|32|"
										"\nadd_checkbox|banUser|`4BAN from game|" + status_ban +
										"\nadd_checkbox|muteUser|`4MUTE|" + status_mute +
										"\nadd_checkbox|curseUser|`4CURSE|" + status_curse +
										"|"
										"\nadd_text_input|timeUser|`wTime (Hour(s)):|0|10|"
										"\nadd_quick_exit|\n\nend_dialog|punishUser_" + to_string(((PlayerInfo*)(peer->data))->lastUserID) + "|Cancel|Apply|";
									;
									Player::OnDialogRequest(peer, punishOptions);
								}
							}
						}
						if (btn == "freeze_" + ((PlayerInfo*)(peer->data))->userID) {
							if (((PlayerInfo*)(peer->data))->adminLevel < 2) continue;
							ENetPeer* currentPeer;
							for (currentPeer = server->peers;
								currentPeer < &server->peers[server->peerCount];
								++currentPeer)
							{
								if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
									continue;
								if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
									Player::OnConsoleMessage(peer, "Working...");
									Player::OnConsoleMessage(peer, "`oPunishment (`1FREEZE`o) sent to " + ((PlayerInfo*)(peer->data))->displayName);
									((PlayerInfo*)(currentPeer->data))->isFrozen = true;
									sendState(currentPeer);
									savePunishment(currentPeer);
								}
							}
						}
						/*if (btn == "wban") {
							WorldInfo* worldz = getPlyersWorld(peer);
							if (!worldz) continue;
							if (isWorldOwner(peer, worldz) || ((PlayerInfo*)(peer->data))->adminLevel >= 2) {

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (peer != currentPeer) {
										if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
											Player::OnConsoleMessage(currentPeer, "`oYou have been `4world banned `ofrom `w" + worldz->name + "`o.``");
											Player::OnConsoleMessage(peer, "`4Banned `w" + ((PlayerInfo*)(currentPeer->data))->displayName + " `ofrom world for 1 hour.``");
											sendPlayerLeave(currentPeer, (PlayerInfo*)(currentPeer->data));
											sendWorldOffers(currentPeer);


											((PlayerInfo*)(currentPeer->data))->currentWorld = "EXIT";
											Player::PlayAudio(peer, "audio/repair.wav", 128);
											try {
												WorldAdministration w;
												w.userID = atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str());
												w.bannedAt = GetCurrentTimeInternalSeconds() + 3600;
												world->wbans.push_back(w);
											}
											catch (...) {
												break;
											}
											break;
										}
									}
								}
							}
						}*/
						if (btn == "kick") {
							if (!world) continue;
							if (world->owner == ((PlayerInfo*)(peer->data))->rawName || ((PlayerInfo*)(peer->data))->adminLevel >= 2) {

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (peer != currentPeer) {
										if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
											playerRespawn(currentPeer, false);
										}
									}
								}
							}
						}
						if (btn == "pull") {
							if (!world) continue;
							int xs; int ys;
							int netid;
							if (world->owner == ((PlayerInfo*)(peer->data))->rawName || ((PlayerInfo*)(peer->data))->adminLevel >= 2) {

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (peer != currentPeer) {
										if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
											Player::OnSetPos(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, 0);
											xs = ((PlayerInfo*)(currentPeer->data))->x;
											ys = ((PlayerInfo*)(currentPeer->data))->y;
											netid = ((PlayerInfo*)(currentPeer->data))->netID;
											Player::PlayAudio(peer, "audio/object_spawn.wav", 150);
											Player::PlayAudio(currentPeer, "audio/object_spawn.wav", 150);
											if (((PlayerInfo*)(peer->data))->invis == true) {
												Player::OnTextOverlay(currentPeer, "You were summoned by a mod.");
											}
											else {
												Player::OnTextOverlay(currentPeer, "You were pulled by " + ((PlayerInfo*)(peer->data))->displayName);
											}
										}
									}
									if (isHere(peer, currentPeer)) {
										pullEffect(currentPeer, xs, ys, netid, 0);
										pullEffect(currentPeer, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(peer->data))->netID, 0);

									}
								}
							}
							else {
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (peer != currentPeer) {
										if (((PlayerInfo*)(peer->data))->lastUserID == atoi((((PlayerInfo*)(currentPeer->data))->userID).c_str())) {
											Player::OnSetPos(currentPeer, ((PlayerInfo*)(currentPeer->data))->netID, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, 0);
											Player::PlayAudio(peer, "audio/object_spawn.wav", 150);
											Player::PlayAudio(currentPeer, "audio/object_spawn.wav", 150);
											Player::OnTextOverlay(currentPeer, "You were pulled by " + ((PlayerInfo*)(peer->data))->displayName);
										}
									}
									if (isHere(peer, currentPeer)) {
										pullEffect(currentPeer, xs, ys, netid, 0);
										pullEffect(currentPeer, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(peer->data))->netID, 0);

									}
								}
							}
						}

						if (aaprequest) {
							if (((PlayerInfo*)(peer->data))->AAP == AAPcode) {
								((PlayerInfo*)(peer->data))->AAPfirst = false;
								sendnews(peer);
							}
							else {
								((PlayerInfo*)(peer->data))->AAPfirst = true;
								string AAPdialog = (
									"set_default_color|`o\n\nadd_label_with_icon|big|`wAdvanced Account Protection``|left|242|\n\nadd_spacer|small|\nadd_smalltext|`wThis account is protected, if you are owner of this account please enter the verification code you created before.|\nadd_text_input|AAPcode|Verification code:||5|\nend_dialog|aaprequest|Cancel|`2Verify|\n"
									);
								Player::OnDialogRequest(peer, AAPdialog);

							}
						}
#ifdef REGISTRATION
						if (isRegisterDialog) {

							int regState = PlayerDB::playerRegister(peer, username, password, passwordverify, email, discord);
							if (regState == 1) {
								packet::consolemessage(peer, "`rYour account has been created!``");
								gamepacket_t p;
								p.Insert("SetHasGrowID");
								p.Insert(1);
								p.Insert(username);
								p.Insert(password);
								p.CreatePacket(peer);
								gamepacket_t c;
								c.Insert("OnSendToServer");
								c.Insert(17091);
								c.Insert(1);
								c.Insert(237);
								c.Insert("20.83.176.110|");
								c.Insert(1);
								c.CreatePacket(peer);

							}
							else if (regState == -1) {
								packet::consolemessage(peer, "`rAccount creation has failed, because it already exists!``");
							}
							else if (regState == -2) {
								packet::consolemessage(peer, "`rAccount creation has failed, because the name is too short!``");
							}
							else if (regState == -3) {
								packet::consolemessage(peer, "`4Passwords mismatch!``");
							}
							else if (regState == -4) {
								packet::consolemessage(peer, "`4Account creation has failed, because email address is invalid!``");
							}
							else if (regState == -5) {
								packet::consolemessage(peer, "`4Account creation has failed, because Discord ID is invalid!``");
							}
						}
#endif
					}
					string dropText = "action|drop\n|itemID|"; // drop function
					if (cch.find(dropText) == 0)
					{
						//cout << "#dropped" << endl;
						if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
							
							if (((PlayerInfo*)(peer->data))->isCursed == true)
							{
								Player::OnConsoleMessage(peer, "`4You are cursed now!");
								continue;
							}
							std::stringstream ss(cch);
							std::string to;
							int idx = -1;
							int count = -1;
							while (std::getline(ss, to, '\n')) {
								vector<string> infoDat = explode("|", to);
								if (infoDat.size() == 3) {
									if (infoDat[1] == "itemID") idx = atoi(infoDat[2].c_str());
									if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
								}
							}
							((PlayerInfo*)(peer->data))->lastdropitem = idx;
							((PlayerInfo*)(peer->data))->lastdropitemcount = count;
							if (idx == -1) continue;
							if (itemDefs.size() < idx || idx < 0) continue;
							if (((PlayerInfo*)(peer->data))->lastdropitem == 18 || ((PlayerInfo*)(peer->data))->lastdropitem == 32 || ((PlayerInfo*)(peer->data))->lastdropitem == 6336 || ((PlayerInfo*)(peer->data))->lastdropitem == 8552 || ((PlayerInfo*)(peer->data))->lastdropitem == 1738 || ((PlayerInfo*)(peer->data))->lastdropitem == 9482 || ((PlayerInfo*)(peer->data))->lastdropitem == 9356 || ((PlayerInfo*)(peer->data))->lastdropitem == 9492 || ((PlayerInfo*)(peer->data))->lastdropitem == 1672 || ((PlayerInfo*)(peer->data))->lastdropitem == 8774 || ((PlayerInfo*)(peer->data))->lastdropitem == 1790 || ((PlayerInfo*)(peer->data))->lastdropitem == 2592 || ((PlayerInfo*)(peer->data))->lastdropitem == 1784 || ((PlayerInfo*)(peer->data))->lastdropitem == 1792 || ((PlayerInfo*)(peer->data))->lastdropitem == 1794 || ((PlayerInfo*)(peer->data))->lastdropitem == 7734 || ((PlayerInfo*)(peer->data))->lastdropitem == 8306 || ((PlayerInfo*)(peer->data))->lastdropitem == 3162) {
								Player::OnTextOverlay(peer, "You can't drop that.");
								continue;
							}
							else {
								Player::OnDialogRequest(peer, "add_label_with_icon|big|`wDrop " + itemDefs.at(idx).name + "``|left|" + std::to_string(idx) + "|\nadd_textbox|`oHow many to drop?|\nadd_text_input|dropitemcount|||3||\nadd_textbox|`4Warning: `oAny player who asks you to drop items is scamming you. We cannot restore scammed items.|\nend_dialog|dropdialog|Cancel|Ok|\n");
								continue;
							}
						}
						else {
							Player::OnTextOverlay(peer, "`^This Feature Only `9Available `^For Registered Players!");
						}
					}
					string trashText = "action|trash\n|itemID|"; // drop funkcianalumas
					if (cch.find(trashText) == 0)
					{
						//cout << "#trashas" << endl;
						std::stringstream ss(cch);
						std::string to;
						int idx = -1;
						int count = -1;
						while (std::getline(ss, to, '\n')) {
							vector<string> infoDat = explode("|", to);
							if (infoDat.size() == 3) {
								if (infoDat[1] == "itemID") idx = atoi(infoDat[2].c_str());
								if (infoDat[1] == "count") count = atoi(infoDat[2].c_str());
							}
						}
						((PlayerInfo*)(peer->data))->lasttrashitem = idx;
						((PlayerInfo*)(peer->data))->lasttrashitemcount = count;
						if (idx == -1) continue;
						if (itemDefs.size() < idx || idx < 0) continue;
						if (((PlayerInfo*)(peer->data))->lasttrashitem == 18 || ((PlayerInfo*)(peer->data))->lasttrashitem == 32 || ((PlayerInfo*)(peer->data))->lasttrashitem == 6336 || ((PlayerInfo*)(peer->data))->lasttrashitem == 8552 || ((PlayerInfo*)(peer->data))->lasttrashitem == 1738 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9482 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9356 || ((PlayerInfo*)(peer->data))->lasttrashitem == 9492 || ((PlayerInfo*)(peer->data))->lasttrashitem == 1672 || ((PlayerInfo*)(peer->data))->lasttrashitem == 8774 || ((PlayerInfo*)(peer->data))->lasttrashitem == 1790 || ((PlayerInfo*)(peer->data))->lasttrashitem == 2592 || ((PlayerInfo*)(peer->data))->lasttrashitem == 1784 || ((PlayerInfo*)(peer->data))->lasttrashitem == 1792 || ((PlayerInfo*)(peer->data))->lasttrashitem == 1794 || ((PlayerInfo*)(peer->data))->lasttrashitem == 7734 || ((PlayerInfo*)(peer->data))->lasttrashitem == 8306 || ((PlayerInfo*)(peer->data))->lasttrashitem == 3162) {
							Player::OnTextOverlay(peer, "You can't trash that.");
							continue;
						}
						else {
							Player::OnDialogRequest(peer, "add_label_with_icon|big|`wTrash " + itemDefs.at(idx).name + "``|left|" + std::to_string(idx) + "|\nadd_textbox|`oHow many to trash?|\nadd_text_input|trashitemcount|||3|\nend_dialog|trashdialog|Cancel|Ok|\n");
						}
					}
					if (cch.find("text|") != std::string::npos) {
						PlayerInfo* pData = ((PlayerInfo*)(peer->data));
						if (((PlayerInfo*)(peer->data))->haveGrowId == false) {
							Player::OnConsoleMessage(peer, "`oCreate GrowID First!");
							continue;
						}
						if (str.length() && str[0] == '/')
						{
							packet::consolemessage(peer, "`6" + str);

							if (str == "/help") {
								
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									packet::consolemessage (peer, "Supported commands are`o: /wave, /dance, /love, /sleep, /fp, /yes, /no, /omg, /idk, /furious, /rolleyes, /fold, /dab, /sassy, /dance2, /msg <name> <message>, /mods, /help, /ghost, /inventory, /color <Num>, /who, /state <Num>, /count, /sb <message>, /radio, /find <item-name>, /unequip, /weather <Num>/asb <message>, /remove <name>, /giveadmin <name>, /giveco <name>, /givemod <name>, /restart (buggy) , /restartcount (count only), /stop (buggy. need some fixes later), /clearcache, /selfban ");
								}
								if (((PlayerInfo*)(peer->data))->adminLevel == 2) {
									
									packet::consolemessage (peer, "Supported commands are`o: /wave, /dance, /love, /sleep, /fp, /yes, /no, /omg, /idk, /furious, /rolleyes, /fold, /dab, /sassy, /dance2, /msg <name> <message>, /mods, /help, /ghost, /inventory, /color <Num>, /who, /state <Num>, /count, /sb <message>, /radio, /find <item-name>, /unequip, /weather <Num>/ban <name>, /mute <name>, /nick <name>, /summon <name>, /warpto <name>, /magic, /invis, /clearworld, /boot (disconnect all players from world except your self)"); //mod|admin|co
								}
								
							}
							else if (str == "/stop") {
								for (ENetPeer* currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED || currentPeer->data == NULL) continue;
									GlobalMaintenance = true;
									Player::OnConsoleMessage(currentPeer, "`5Server is saving and shutting down... (Maintenance)");
									Player::PlayAudio(currentPeer, "audio/boo_pke_warning_light.wav", 0);
									enet_peer_disconnect_later(currentPeer, 0);
								}
							}
							else if (str == "/clearcache") {
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									PlayerMoving data;
									data.packetType = 39;
									SendPacketRaw1(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE, 0);
								}
							}
							if (str == "/p ") {
								(((PlayerInfo*)(peer->data))->effect = atoi(str.substr(3, cch.length() - 3 - 1).c_str()));
								sendPuncheffect(peer, (((PlayerInfo*)(peer->data))->effect));
								send_state(peer);
								packet::consolemessage(peer, "`oPunch Effect changed!");
							}
							else if (str.substr(0, 6) == "/mute ") {
								if (!isMod(peer)) {
									string name = str.substr(6, str.length());

									ENetPeer* currentPeer;

									bool found = false;
									if (name == "") {
										Player::OnConsoleMessage(peer, "`oNo name entered.");
										continue;
									}
									else {
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;

											if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
												found = true;
												if (((PlayerInfo*)(currentPeer->data))->taped == true) {
													((PlayerInfo*)(currentPeer->data))->taped = false;
													((PlayerInfo*)(currentPeer->data))->isDuctaped = false;

													packet::consolemessage(currentPeer, "`oYou are no longer duct-taped! (`$Duct Tape `omod removed).");
													sendState(currentPeer);
													{
														gamepacket_t p;
														p.Insert("OnConsoleMessage");
														p.Insert("`oPunishment Removed From `w" + ((PlayerInfo*)(peer->data))->displayName + " `otype `4duct-tape");
														p.CreatePacket(peer);
														saveOptions(currentPeer);
														savePunishment(currentPeer);
													}
												}
												else {
													((PlayerInfo*)(currentPeer->data))->taped = true;
													((PlayerInfo*)(currentPeer->data))->isDuctaped = true;
													saveOptions(currentPeer);
													savePunishment(currentPeer);
													gamepacket_t p;
													p.Insert("OnConsoleMessage");
													p.Insert("`oDuct tape has covered your mouth! (`$Duct Tape `omod added, `$730 `odays left)");
													p.CreatePacket(currentPeer);
													Player::OnConsoleMessage(currentPeer, "`oWarning from `4SYSTEM`o: You've been `4duct-taped `ofor 730 days");
													gamepacket_t ps;
													ps.Insert("OnAddNotification");
													ps.Insert("interface/atomic_button.rttex");
													ps.Insert("`wWarning from `4SYSTEM`w: You've been `4duct-taped `wfor 730 days");
													ps.Insert("audio/hub_open.wav");
													ps.Insert(0);
													ps.CreatePacket(currentPeer);
													sendState(currentPeer);
													{
														gamepacket_t p;
														p.Insert("OnConsoleMessage");
														p.Insert("`oPunishment Applied To `w" + ((PlayerInfo*)(peer->data))->displayName + " `otype `4duct-tape `ofor 730 days left");
														p.CreatePacket(peer);
														Player::OnConsoleMessage(currentPeer, "`#**`$The Ancient Ones `ohave `4duct-taped `w" + name + "'s mouth`# **`o(`4/rules`o to see the rules!)");
														break;
													}
												}
											}
										}
										if (!found) {
											gamepacket_t p;
											p.Insert("OnConsoleMessage");
											p.Insert("`oPlayer not found.");
											p.CreatePacket(peer);
										}
									}
								}
							}

							else if (str == "/boot") {
								if (((PlayerInfo*)(peer->data))->adminLevel >= 2) {
									if (world) {
										Player::OnConsoleMessage(peer, "`oAttempting to disconnect every player in this world`w...");
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												if (peer != currentPeer) {
													enet_peer_disconnect_later(currentPeer, 0);
												}
											}
										}
									}
								}
							}
							else if (str.substr(0, 8) == "/summon ") {
								if (!isMod(peer)) {
									string name = str.substr(8, str.length());

									ENetPeer* currentPeer;

									bool found = false;
									if (name == "") {
										Player::OnConsoleMessage(peer, "`oNo name entered.");
										continue;
									}
									else {
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;

											if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
												found = true;
												((PlayerInfo*)(currentPeer->data))->bypass_underscore = true; //Biar bisa di summon ke world yg ada "under score: _ nya".
												joinWorld(currentPeer, ((PlayerInfo*)(peer->data))->currentWorld);
												Player::OnTextOverlay(currentPeer, "`wYou were summoned by a mod.");

											}
											else {
												Player::OnTextOverlay(currentPeer, "`wPlayer not found.");
												break; //change to continue if there is problem.
											}
										}
									}
								}
							}
							else if (str.substr(0, 5) == "/ban ") {
								if (((PlayerInfo*)(peer->data))->adminLevel >= 2) {
									string name = str.substr(5, str.length());

									ENetPeer* currentPeer;

									bool found = false;
									if (name == "") {
										Player::OnConsoleMessage(peer, "`oNo name entered.");
										continue;
									}
									else {
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;

											if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
												found = true;
												((PlayerInfo*)(currentPeer->data))->banned = true;
												((PlayerInfo*)(currentPeer->data))->bantape = true;
												saveOptions(currentPeer);
												savePunishment(currentPeer);
												gamepacket_t p;
												p.Insert("OnConsoleMessage");
												p.Insert("`oreality flickers as you begin to wake up! (`$Ban `omod added, `$730 `odays left)");
												p.CreatePacket(currentPeer);
												Player::OnConsoleMessage(currentPeer, "`oWarning from `4SYSTEM`o: You've been `4BANNED `ofrom Growtopia `ofor 730 days");
												gamepacket_t ps;
												ps.Insert("OnAddNotification");
												ps.Insert("interface/atomic_button.rttex");
												ps.Insert("`wWarning from `4SYSTEM`w: You've been `4BANNED `wfrom Growtopia `wfor 730 days");
												ps.Insert("audio/hub_open.wav");
												ps.Insert(0);
												ps.CreatePacket(currentPeer);
												sendState(currentPeer);
												enet_peer_disconnect_later(currentPeer, 0);
												{
													gamepacket_t p;
													p.Insert("OnConsoleMessage");
													p.Insert("`oPunishment Applied To `w" + ((PlayerInfo*)(peer->data))->displayName + " `otype `4ban `ofor 730 days left");
													p.CreatePacket(peer);
													Player::OnConsoleMessage(currentPeer, "`#**`$The Ancient Ones `ohave `4banned `w" + name + "`# **`o(`4/rules`o to see the rules!)");
													break;
												}
											}
										}
										if (!found) {
											gamepacket_t p;
											p.Insert("OnConsoleMessage");
											p.Insert("`oPlayer not found.");
											p.CreatePacket(peer);
										}
									}
								}
								else {
									gamepacket_t p;
									p.Insert("OnConsoleMessage");
									p.Insert("`oNo.");
									p.CreatePacket(peer);
								}
							}
							else if (str.substr(0, 8) == "/remove ") {
								if (((PlayerInfo*)(peer->data))->adminLevel < 5) continue;
								string strs = str.substr(8, str.length());
								bool found;
								if (strs == "") {
									Player::OnConsoleMessage(peer, "No name entered.");
									continue;
								}
								else {
									std::ifstream ifff("playersPunishment/" + strs + ".json");
									if (ifff.fail()) {

										found = false;
										ifff.close();
									}
									if (ifff.is_open()) {
										found = true;
									}


									if (found == false) {
										Player::OnConsoleMessage(peer, "Player database not found.");
										continue;
									}
									else {
										json j;
										ifff >> j; //load
										j["isBanned"] = false;
										std::ofstream o("playersPunishment/" + strs + ".json"); //save
										if (!o.is_open()) {
											cout << GetLastError() << endl;
											_getch();
										}
										o << j << std::endl;
										Player::OnConsoleMessage(peer, "`oRemoved ban from " + strs);
									}
								}
							}
							else if (str == "/invis" || str == "/invisible") {
								if (((PlayerInfo*)(peer->data))->adminLevel >= 2) {
									int peernetid = ((PlayerInfo*)(peer->data))->netID;
									PlayerInfo* pData = ((PlayerInfo*)(peer->data));
									//sendConsoleMsg(peer, "`6" + str);
									if (pData->invis == 0) {
										Player::OnConsoleMessage(peer, "`oYou are now ninja, invisible to all.");
										OnInvisV2(peer, 1, peernetid);
										((PlayerInfo*)(peer->data))->invis = 1;
										//savejson(peer);

										ENetPeer* currentPeer;

										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												bool isRev = false;
												for (ENetPeer* currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
													if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
													if (isHere(peer, currentPeer)) {
														Player::PlayAudio(currentPeer, "audio/magic.wav", 0);
														for (int i = 0; i < 14; i++) {
															if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);
															if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);
															if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);
															if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);

															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 16, 3, i * 300);
															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 16, 3, i * 300);
															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 16, 3, i * 300);
															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 16, 3, i * 300);

															/*if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x - 15 * (rand() % 6), y - 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);
															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x + 15 * (rand() % 6), y - 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);
															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x + 15 * (rand() % 6), y + 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);
															if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x - 15 * (rand() % 6), y + 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);*/
														}
													}
												}
												OnInvisV2(currentPeer, 1, peernetid);
											}
										}
									}
									else {
										Player::OnConsoleMessage(peer, "`oYou are once again visible to mortals.");
										OnInvisV2(peer, 0, peernetid);
										pData->invis = 0;
										//savejson(peer);
										ENetPeer* currentPeer;
										for (currentPeer = server->peers;
											currentPeer < &server->peers[server->peerCount];
											++currentPeer)
										{
											if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
												continue;
											if (isHere(peer, currentPeer))
											{
												bool isRev = false;
												bool isOffInvis = false;
												for (int i = 5; i < 15; i++) {
													if (isRev == false) {
														effectbarrel(currentPeer, ((PlayerInfo*)(peer->data))->x + i * (rand() % 9), ((PlayerInfo*)(peer->data))->y + i * (rand() % 9), ((PlayerInfo*)(peer->data))->netID, i * 200);
														Player::OnParticleEffect(currentPeer, 3, ((PlayerInfo*)(peer->data))->x + i * (rand() % -10), ((PlayerInfo*)(peer->data))->y + i * (rand() % 9), i * 200);
														Player::OnParticleEffect(currentPeer, 2, ((PlayerInfo*)(peer->data))->x + i * (rand() % -10), ((PlayerInfo*)(peer->data))->y + i * (rand() % 9), i * 200);
														isRev = true;
													}
													else {
														effectbarrel(currentPeer, ((PlayerInfo*)(peer->data))->x + i * (rand() % 9), ((PlayerInfo*)(peer->data))->y + i * (rand() % 9), ((PlayerInfo*)(peer->data))->netID, i * 200);
														Player::OnParticleEffect(currentPeer, 3, ((PlayerInfo*)(peer->data))->x + i * (rand() % -10), ((PlayerInfo*)(peer->data))->y + i * (rand() % 9), i * 200);
														Player::OnParticleEffect(currentPeer, 2, ((PlayerInfo*)(peer->data))->x + i * (rand() % -10), ((PlayerInfo*)(peer->data))->y + i * (rand() % 9), i * 200);
														isRev = false;
														isOffInvis = true;
													}
												}
												if (isOffInvis == true) {
													OnInvisV2(currentPeer, 0, peernetid);
													isOffInvis = false;
												}
											}
										}
									}
								}
							}
							else if (str == "/magic2") {
								if (((PlayerInfo*)(peer->data))->adminLevel >= 2) {
									if (!world) continue;
									float x = ((PlayerInfo*)(peer->data))->x;
									float y = ((PlayerInfo*)(peer->data))->y;
									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
									}

									bool found = false;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer)) {
											Player::PlayAudio(currentPeer, "audio/magic.wav", 0);
											bool isRev = false;
											for (int i = 0; i < 15; i++) {
												effectbarrel(currentPeer, x + i * (rand() % 9), y + i * (rand() % 9), ((PlayerInfo*)(peer->data))->netID, i * 200);
												Player::OnParticleEffect(currentPeer, 3, x + i * (rand() % -10), y + i * (rand() % 9), i * 200);
												Player::OnParticleEffect(currentPeer, 2, x + i * (rand() % -10), y + i * (rand() % 9), i * 200);
												isRev = true;
												effectbarrel(currentPeer, x + i * (rand() % 9), y + i * (rand() % 9), ((PlayerInfo*)(peer->data))->netID, i * 200);
												Player::OnParticleEffect(currentPeer, 3, x + i * (rand() % -10), y + i * (rand() % 9), i * 200);
												Player::OnParticleEffect(currentPeer, 2, x + i * (rand() % -10), y + i * (rand() % 9), i * 200);
												isRev = false;
											}
										}
									}
								}
							}
							else if (str == "/magic") {
								for (ENetPeer* currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED) continue;
									if (isHere(peer, currentPeer)) {
										Player::PlayAudio(currentPeer, "audio/magic.wav", 0);
										for (int i = 0; i < 14; i++) {
											if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);
											if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);
											if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);
											if (rand() % 100 <= 75) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 6 + 1, 2, i * 300);

											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 16, 3, i * 300);
											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y - 15 * (rand() % 6), rand() % 16, 3, i * 300);
											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x + 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 16, 3, i * 300);
											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, static_cast<PlayerInfo*>(peer->data)->x - 15 * (rand() % 6), static_cast<PlayerInfo*>(peer->data)->y + 15 * (rand() % 6), rand() % 16, 3, i * 300);

											/*if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x - 15 * (rand() % 6), y - 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);
											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x + 15 * (rand() % 6), y - 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);
											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x + 15 * (rand() % 6), y + 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);
											if (rand() % 100 <= 25) SendParticleEffect(currentPeer, x - 15 * (rand() % 6), y + 15 * (rand() % 6), rand() % 16, 57, i * rand() % 3000);*/
										}
									}
								}
							}
							else if (str.substr(0, 6) == "/nick ") {
								if (((PlayerInfo*)(peer->data))->adminLevel < 2) continue;
								string nam1e = "``" + str.substr(6, cch.length() - 6 - 1) + "``";
								if (str.substr(6, cch.length() - 6 - 1) == "") {
									((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(peer->data))->displayNameBackup;
									gamepacket_t ps(0, ((PlayerInfo*)(peer->data))->netID);
									ps.Insert("OnNameChanged");
									ps.Insert(((PlayerInfo*)(peer->data))->displayNameBackup);
									((PlayerInfo*)(peer->data))->isnicked = false;

									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											ps.CreatePacket(currentPeer);
											sendState2(currentPeer, ((PlayerInfo*)(peer->data))->netID);
										}
									}
								}
								else {
									((PlayerInfo*)(event.peer->data))->displayName = str.substr(6, cch.length() - 6 - 1);
									gamepacket_t p(0, ((PlayerInfo*)(peer->data))->netID);
									p.Insert("OnNameChanged");
									p.Insert(nam1e);
									((PlayerInfo*)(peer->data))->isnicked = true;

									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											p.CreatePacket(currentPeer);
											sendState2(currentPeer, ((PlayerInfo*)(peer->data))->netID);
										}
									}
								}
							}
							else if (str.substr(0, 5) == "/asb ") {
								if (((PlayerInfo*)(peer->data))->adminLevel < 5) continue;

								gamepacket_t p;
								p.Insert("OnAddNotification");
								p.Insert("interface/atomic_button.rttex");
								p.Insert(str.substr(4, cch.length() - 4 - 1).c_str());
								p.Insert("audio/hub_open.wav");
								p.Insert(0);

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									p.CreatePacket(currentPeer);
								}
							}
							else if (str == "/restartcount") {
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									cout << "Restart from " << ((PlayerInfo*)(peer->data))->displayName << endl;

									gamepacket_t p;
									p.Insert("OnConsoleMessage");
									p.Insert("**Global System Message: `4Server Restart for update!");

									gamepacket_t p2;
									p2.Insert("OnConsoleMessage");
									p2.Insert("`4Global System Message``: ``Restarting server for update in `41 ``minute");

									gamepacket_t p3(10000);
									p3.Insert("OnConsoleMessage");
									p3.Insert("`4Global System Message``: Restarting server for update in `450 ``seconds");

									gamepacket_t p4(20000);
									p4.Insert("OnConsoleMessage");
									p4.Insert("`4Global System Message``: Restarting server for update in `440 ``seconds");

									gamepacket_t p5(30000);
									p5.Insert("OnConsoleMessage");
									p5.Insert("`4Global System Message``: Restarting server for update in `430 ``seconds");

									gamepacket_t p6(40000);
									p6.Insert("OnConsoleMessage");
									p6.Insert("`4Global System Message``: Restarting server for update in `420 ``seconds");

									gamepacket_t p7(50000);
									p7.Insert("OnConsoleMessage");
									p7.Insert("`4Global System Message``: Restarting server for update in `410 ``seconds");

									gamepacket_t p8(51000);
									p8.Insert("OnConsoleMessage");
									p8.Insert("`4Global System Message``: Restarting server for update in `49 ``seconds");

									gamepacket_t p9(52000);
									p9.Insert("OnConsoleMessage");
									p9.Insert("`4Global System Message``: Restarting server for update in `48 ``seconds");

									gamepacket_t p10(53000);
									p10.Insert("OnConsoleMessage");
									p10.Insert("`4Global System Message``: Restarting server for update in `47 ``seconds");

									gamepacket_t p11(54000);
									p11.Insert("OnConsoleMessage");
									p11.Insert("`4Global System Message``: Restarting server for update in `46 ``seconds");

									gamepacket_t p12(55000);
									p12.Insert("OnConsoleMessage");
									p12.Insert("`4Global System Message``: Restarting server for update in `45 ``seconds");

									gamepacket_t p13(56000);
									p13.Insert("OnConsoleMessage");
									p13.Insert("`4Global System Message``: Restarting server for update in `44 ``seconds");

									gamepacket_t p14(57000);
									p14.Insert("OnConsoleMessage");
									p14.Insert("`4Global System Message``: Restarting server for update in `43 ``seconds");

									gamepacket_t p15(58000);
									p15.Insert("OnConsoleMessage");
									p15.Insert("`4Global System Message``: Restarting server for update in `42 ``seconds");

									gamepacket_t p16(59000);
									p16.Insert("OnConsoleMessage");
									p16.Insert("`4Global System Message``: Restarting server for update in `41 ``seconds");

									gamepacket_t p17(60000);
									p17.Insert("OnConsoleMessage");
									p17.Insert("`4Global System  Message``: Restarting server for update in `4ZERO ``seconds! Should be back up in a minute or so. BYE!");

									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										p.CreatePacket(currentPeer);
										p2.CreatePacket(currentPeer);
										p3.CreatePacket(currentPeer);
										p4.CreatePacket(currentPeer);
										p5.CreatePacket(currentPeer);
										p6.CreatePacket(currentPeer);
										p7.CreatePacket(currentPeer);
										p8.CreatePacket(currentPeer);
										p9.CreatePacket(currentPeer);
										p10.CreatePacket(currentPeer);
										p11.CreatePacket(currentPeer);
										p12.CreatePacket(currentPeer);
										p13.CreatePacket(currentPeer);
										p14.CreatePacket(currentPeer);
										p15.CreatePacket(currentPeer);
										p16.CreatePacket(currentPeer);
										p17.CreatePacket(currentPeer);
									}
								}
							}
							/*else if (str == "/down") {
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									packet::consolemessage(peer, "Attempting to down the server.");
									enet_peer_disconnect;
								}
							}*/
							else if (str == "/restart") {
								if (restartForUpdate)
								{
									continue;
								}
								
								GamePacket p = packetEnd(appendInt(appendString(appendString(appendString(appendString(createPacket(), "OnAddNotification"), "interface/science_button.rttex"), "Restarting For Update!"), "audio/mp3/suspended.mp3"), 0));
								ENetPacket* packet = enet_packet_create(p.data,
									p.len,
									ENET_PACKET_FLAG_RELIABLE);
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									enet_peer_send(currentPeer, 0, packet);
								}
								delete p.data;
								restartForUpdate = true;
								GlobalMaintenance = true;
								thread restartthread(RestartForUpdate);
								if (restartthread.joinable()) {
									restartthread.detach();
								}

							}
							else if (str == "/clearworld") {
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									vector<WorldInfo> worlds;
									WorldInfo* wrld = getPlyersWorld(peer);
									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (((PlayerInfo*)(currentPeer->data))->currentWorld == wrld->name)
										{
											string act = ((PlayerInfo*)(peer->data))->currentWorld;
											int x = 3040;
											int y = 736;
											for (int i = 0; i < world->width * world->height; i++)
											{
												if (world->items[i].foreground == 6) {

												}
												else if (world->items[i].foreground == 8) {

												}
												else if (getItemDef(world->items[i].foreground).properties & Property_Permanent) {

												}
												else {
													world->items[i].foreground = 0;
													world->items[i].background = 0;
													world->items[i].isMultifacing = false;

												}
											}
										}
									}
									bool found = false;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;

										if (((PlayerInfo*)(peer->data))->currentWorld == ((PlayerInfo*)(currentPeer->data))->currentWorld)
										{
											joinWorld(currentPeer, ((PlayerInfo*)(peer->data))->currentWorld);
										}


									}
								}
							}
							/*else if (str == "/ghost")
							{
								if (((PlayerInfo*)(peer->data))->canWalkInBlocks == false) {
									((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
									sendState(peer);
									savejson(peer);
									packet::consolemessage(peer, "`oYour atoms are suddenly aware of quantum tunneling. (`$Ghost in the Shell `omod added)``");
									Player::PlayAudio(peer, "audio/dialog_confirm.wav", 0);
								}
								else {
									((PlayerInfo*)(peer->data))->canWalkInBlocks = false;
									sendState(peer);
									savejson(peer);
									Player::OnConsoleMessage(peer, "`oYour body stops shimmering and returns to normal. (`$Ghost in the Shell `omod removed)``");
									Player::PlayAudio(peer, "audio/dialog_confirm.wav", 0);
								}
							}*/
							if (str == "/ghost")
							{
								ENetPeer* currentPeer;
								int netid = ((PlayerInfo*)(peer->data))->netID;
								if (((PlayerInfo*)(peer->data))->canWalkInBlocks == false) {
									((PlayerInfo*)(peer->data))->canWalkInBlocks = true;
									sendState(peer);

									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										//effectbarrel(currentPeer, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(currentPeer->data))->netID, 0);
										Player::OnChangeSkin(currentPeer, -160, ((PlayerInfo*)(peer->data))->netID); // -137
									}
									Player::OnConsoleMessage(peer, "`oYour atoms are suddenly aware of quantum tunneling. (`$Ghost in the Shell `omod added)``");
								}
								else {
									((PlayerInfo*)(peer->data))->canWalkInBlocks = false;

									sendState(peer);
									Player::PlayAudio(peer, "audio/dialog_confirm.wav", 0);
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										//effectbarrel(currentPeer, ((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y, ((PlayerInfo*)(peer->data))->netID, 0);
										Player::OnChangeSkin(currentPeer, ((PlayerInfo*)(peer->data))->skinColor, netid);
									}

									Player::OnConsoleMessage(peer, "`oYour body stops shimmering and returns to normal. (`$Ghost in the Shell `omod removed)``");
								}
							}
							/*else if (str == "/freezeall") {
								int howmuch = 0;
								for (ENetPeer* currentPeer = server->peers; currentPeer < &server->peers[server->peerCount]; ++currentPeer) {
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED || currentPeer->data == NULL) continue;
									if (isHere(peer, currentPeer) && static_cast<PlayerInfo*>(currentPeer->data)->rawName != static_cast<PlayerInfo*>(peer->data)->rawName)
									{
										try {
											if (!static_cast<PlayerInfo*>(currentPeer->data)->frozen)
											{
												GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 1));
												memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
												ENetPacket* packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												static_cast<PlayerInfo*>(currentPeer->data)->skinColor = -120000;
												sendClothes(currentPeer);

												Player::OnTextOverlay(currentPeer, "`oYou have been `1frozen `oby a mod.");
												Player::OnConsoleMessage(currentPeer, "`oThere are so icy right i am so cold now!? (`oFrozen mod added! 30 Seconds Left`o)");
												static_cast<PlayerInfo*>(currentPeer->data)->frozen = true;
												static_cast<PlayerInfo*>(currentPeer->data)->freezetime = GetCurrentTimeInternalSeconds() + 30;
												Player::PlayAudio(currentPeer, "audio/freeze.wav", 0);
											}
											else
											{
												GamePacket p2 = packetEnd(appendIntx(appendString(createPacket(), "OnSetFreezeState"), 0));
												memcpy(p2.data + 8, &(((PlayerInfo*)(currentPeer->data))->netID), 4);
												ENetPacket* packet2 = enet_packet_create(p2.data, p2.len, ENET_PACKET_FLAG_RELIABLE);
												enet_peer_send(currentPeer, 0, packet2);
												delete p2.data;
												static_cast<PlayerInfo*>(currentPeer->data)->skinColor = -2104114177;
												sendClothes(currentPeer);

												Player::OnTextOverlay(currentPeer, "`oYou have been `1unfrozen `oby a mod.");
												Player::OnConsoleMessage(currentPeer, "`oThere are so icy right i am so cold now!? (`oFrozen mod added! 30 Seconds Left`o)");
												static_cast<PlayerInfo*>(currentPeer->data)->frozen = false;
												static_cast<PlayerInfo*>(currentPeer->data)->freezetime = 0;
											}
											howmuch++;
										}
										catch (const std::out_of_range& e) {
											std::cout << e.what() << std::endl;
										}
									}
								}
								Player::OnTextOverlay(peer, "`4" + to_string(howmuch) + " `oplayers were `1frozen`o.");
							}*/
							/*else if (str == "/selfban") {
								Player::OnConsoleMessage(peer, "done");
								WorldAdministration w;
								w.userID = atoi((((PlayerInfo*)(peer->data))->userID).c_str());
								w.bannedAt = GetCurrentTimeInternalSeconds() + 3600;
								world->wbans.push_back(w);
							}*/
							else if (str.substr(0, 7) == "/state ")
							{
								PlayerMoving data;
								data.packetType = 0x14;
								data.characterState = 0x0; // animation
								data.x = 1000;
								data.y = 0;
								data.punchX = 0;
								data.punchY = 0;
								data.XSpeed = 300;
								data.YSpeed = 600;
								data.netID = ((PlayerInfo*)(peer->data))->netID;
								data.plantingTree = atoi(str.substr(7, cch.length() - 7 - 1).c_str());
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
							}
							else if (str.substr(0, 5) == "/msg ") {
								string myName = ((PlayerInfo*)(peer->data))->displayName;

								int adminLevel = ((PlayerInfo*)(peer->data))->adminLevel;
								string inWorld = ((PlayerInfo*)(peer->data))->currentWorld;
								bool found = false;
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									int strs = ((PlayerInfo*)(peer->data))->rawName.length();
									string name = str.substr(5, strs);
									string test = str.substr(strs, str.length());
									if (test.find(name) != string::npos) { //Erase Player Name
										test.erase(1, strs + 1); // +1
									}

									if (((PlayerInfo*)(currentPeer->data))->rawName == name) {
										found = true;
										if (world->isJammed == true) {
											inWorld = "`4JAMMED";
										}
										else {
											inWorld = "`4<HIDDEN>";
										}
										Player::OnConsoleMessage(currentPeer, "CP:0_PL:4_OID:_CT:[MSG]_ `c>> from (`w" + myName + "`c) [`$" + inWorld + "`c] > `$" + test);
										Player::OnPlayPositioned(currentPeer, "audio/pay_time.wav", ((PlayerInfo*)(peer->data))->netID, false, NULL);
									}
									if (found == true) {
										if (adminLevel > 2) {
											Player::OnConsoleMessage(peer, "CP:0_PL:4_OID:_CT:[MSG]_ `c>> (Sent to `w" + name + "`c)\n`4NOTE:");
										}
										else {
											Player::OnConsoleMessage(peer, "CP:0_PL:4_OID:_CT:[MSG]_ `c>> (Sent to `w" + name + "`c)");
										}
									}
									else {
										Player::OnConsoleMessage(peer, "CP:0_PL:4_OID:_CT:[MSG]_ `c>> There are no names that start with `w" + name + "`c!");
										continue;
									}
								}
							}

							else if (str == "/unequip")
							{
								((PlayerInfo*)(peer->data))->cloth_hair = 0;
								((PlayerInfo*)(peer->data))->cloth_shirt = 0;
								((PlayerInfo*)(peer->data))->cloth_pants = 0;
								((PlayerInfo*)(peer->data))->cloth_feet = 0;
								((PlayerInfo*)(peer->data))->cloth_face = 0;
								((PlayerInfo*)(peer->data))->cloth_hand = 0;
								((PlayerInfo*)(peer->data))->cloth_back = 0;
								((PlayerInfo*)(peer->data))->cloth_mask = 0;
								((PlayerInfo*)(peer->data))->cloth_necklace = 0;
								sendClothes(peer);
							}
							else if (str == "/mods") {
								string x;

								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;

									if (((PlayerInfo*)(currentPeer->data))->adminLevel >= 2 && ((PlayerInfo*)(currentPeer->data))->isnicked == false) {
										x.append(((PlayerInfo*)(currentPeer->data))->displayName + "``, ");
									}

								}
								x = x.substr(0, x.length() - 2);
								if (x == "")
								{
									x = "(All are hidden)";
								}
								gamepacket_t p;
								p.Insert("OnConsoleMessage");
								p.Insert("``Moderators online: " + x);
								p.CreatePacket(peer);
							}
							else

							if (str == "/vendtest")
							{
								/*int n = ((PlayerInfo*)(peer->data))->netID;
								((PlayerInfo*)(peer->data))->lastTradeNetID = n;
								((PlayerInfo*)(peer->data))->lastTradeName = ((PlayerInfo*)(peer->data))->displayName;
								//Player::OnStartTrade(peer, n, n);
								Player::OnPlayPositioned(peer, "audio/wood_break.wav", n, false, NULL);*/
								/*PlayerMoving data;
								//data.packetType = 0x14;
								data.packetType = 0x13;
								//data.characterState = 0x924; // animation
								data.characterState = 0x0; // animation
								data.x = 0;
								data.y = 0;
								data.punchX = 242;
								data.punchY = 242;
								data.XSpeed = 0;
								data.YSpeed = 0;
								data.netID = n;
								data.secondnetID = n;
								data.plantingTree = 950;
								SendPacketRaw(4, packTradeAnim(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);*/



							}
							else if (str.substr(0, 6) == "/find ")
							{


								string itemFind = str.substr(6, cch.length() - 6 - 1);
								if (itemFind.length() < 3) {
									Player::OnConsoleMessage(peer, "`4Find items more than `63 `2characters `wplease`o!``");
									Player::OnTalkBubble(peer, ((PlayerInfo*)(peer->data))->netID, "`4Find items more than `63 `2characters `wplease`o!``", 0, false);
									break;
								}
							SKIPFind:;

								string itemLower2;
								vector<ItemDefinition> itemDefsfind;
								for (char c : itemFind) if (c < 0x20 || c>0x7A) goto SKIPFind;
								if (itemFind.length() < 3) goto SKIPFind3;
								for (const ItemDefinition& item : itemDefs)
								{
									string itemLower;
									for (char c : item.name) if (c < 0x20 || c>0x7A) goto SKIPFind2;
									if (!(item.id % 2 == 0)) goto SKIPFind2;
									itemLower2 = item.name;
									std::transform(itemLower2.begin(), itemLower2.end(), itemLower2.begin(), ::tolower);
									if (itemLower2.find(itemLower) != std::string::npos) {
										itemDefsfind.push_back(item);
									}
								SKIPFind2:;
								}
							SKIPFind3:;
								string listMiddle = "";
								string listFull = "";


								for (const ItemDefinition& item : itemDefsfind)
								{
									if (item.name != "") {
										string kys = item.name;
										std::transform(kys.begin(), kys.end(), kys.begin(), ::tolower);
										string kms = itemFind;
										std::transform(kms.begin(), kms.end(), kms.begin(), ::tolower);
										if (kys.find(kms) != std::string::npos)
										{
											int id = item.id;
											int itemid = item.id;
											if (id == 10034 || id == 242 || id == 2408 || id == 1796 || id == 4428 || id == 7188 || id == 8470 || id == 9290 || id == 9308 || id == 9504 || id == 2950 || id == 4802 || id == 5260 || id == 5814 || id == 5980 || id == 9640 || id == 10410 || getItemDef(id).name.find("null") != string::npos || id == 10036 || getItemDef(id).name.find("Mooncake") != string::npos || getItemDef(id).properties & Property_Untradable || getItemDef(id).name.find("Harvest") != string::npos && id != 1830 || getItemDef(id).name.find("Autumn") != string::npos || getItemDef(id).blockType == BlockTypes::COMPONENT || getItemDef(id).properties & Property_Chemical || id == 6 || id == 8 || id == 9350) {
												if (((ServerPermissions*)(peer->data))->freeItems == false) {
													continue;
												}
											}

											listMiddle += "add_button_with_icon|tool" + to_string(item.id) + "|`$" + item.name + "``|left|" + to_string(item.id) + "|" + to_string(item.id) + "|\n";
										}

									}
								}
								if (itemFind.length() < 3) {
									listFull = "add_textbox|`4Search query is less then 3 letters!``|\nadd_spacer|small|\n";
									Player::showWrong(peer, listFull, itemFind);
								}
								else if (itemDefsfind.size() == 0) {
									//listFull = "add_textbox|`4Found no item match!``|\nadd_spacer|small|\n";
									Player::showWrong(peer, listFull, itemFind);

								}
								else {
									if (listMiddle.size() == 0) {
										Player::OnConsoleMessage(peer, "`wNo `3items found`o.");
									}
									else
									{

										GamePacket fff = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "add_label_with_icon|big|`wFound item : " + itemFind + "``|left|6016|\nadd_spacer|small|\nend_dialog|findid|Cancel|\nadd_spacer|big|\n" + listMiddle + "add_quick_exit|\n"));
										ENetPacket* packetd = enet_packet_create(fff.data,
											fff.len,
											ENET_PACKET_FLAG_RELIABLE);
										enet_peer_send(peer, 0, packetd);

										//enet_host_flush(server);
										delete fff.data;
									}
								}

							}
							else if (str == "/save") {
								if (((PlayerInfo*)(peer->data))->adminLevel == 5) {
									saveAllWorlds();
								}
							}
							else if (str == "/news")
							{
								sendnews(peer);
							}
							else if (str == "/loadnews") {
								if (!isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass)) break;
								loadnews();//To load news instead of close server and run it again
							}
							else if (str.substr(0, 6) == "/flag ") {
								int flagid = atoi(str.substr(6).c_str());

								gamepacket_t p(0, ((PlayerInfo*)(peer->data))->netID);
								p.Insert("OnGuildDataChanged");
								p.Insert(1);
								p.Insert(2);
								p.Insert(flagid);
								p.Insert(3);

								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer))
									{
										p.CreatePacket(currentPeer);
									}
								}
							}
							else if (str.substr(0, 9) == "/weather ") {
								if (world->name != "ADMIN") {
									if (world->owner != "") {
										if (((PlayerInfo*)(peer->data))->rawName == world->owner || isSuperAdmin(((PlayerInfo*)(peer->data))->rawName, ((PlayerInfo*)(peer->data))->tankIDPass))

										{
											ENetPeer* currentPeer;

											for (currentPeer = server->peers;
												currentPeer < &server->peers[server->peerCount];
												++currentPeer)
											{
												if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
													continue;
												if (isHere(peer, currentPeer))
												{
													gamepacket_t p;
													p.Insert("OnSetCurrentWeather");
													p.Insert(atoi(str.substr(9).c_str()));
													p.CreatePacket(currentPeer);
													continue;
												}
											}
										}
									}
								}
							}
							else if (str == "/count") {
								int count = 0;
								ENetPeer* currentPeer;
								string name = "";
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									count++;
								}
								packet::consolemessage(peer, "There are " + std::to_string(count) + " people online out of 1024 limit.");
							}
							else if (str.substr(0, 4) == "/sb ") {
								using namespace std::chrono;
								if (((PlayerInfo*)(peer->data))->lastSB + 45000 < (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count())
								{
									((PlayerInfo*)(peer->data))->lastSB = (duration_cast<milliseconds>(system_clock::now().time_since_epoch())).count();
								}
								else {
									packet::consolemessage(peer, "Wait a minute before using the SB command again!");
									continue;
								}
								string inWorld;
								if (world->isJammed == true) {
									inWorld = "`4JAMMED!";
								}
								else if (((PlayerInfo*)(peer->data))->adminLevel > 1) {
									inWorld = "`4JAMMED!";
								}
								else {
									inWorld = ((PlayerInfo*)(peer->data))->currentWorld;
								}
								string name = ((PlayerInfo*)(peer->data))->displayName;
								gamepacket_t p;
								p.Insert("OnConsoleMessage");
								p.Insert("CP:0_PL:4_OID:_CT:[SB]_ `5** from (`w" + name + "`5) [in `$" + inWorld + "`5] **:`` `$ " + str.substr(4, cch.length() - 4 - 1));

								string text = "action|play_sfx\nfile|audio/beep.wav\ndelayMS|0\n";
								BYTE* data = new BYTE[5 + text.length()];
								BYTE zero = 0;
								int type = 3;
								memcpy(data, &type, 4);
								memcpy(data + 4, text.c_str(), text.length());
								memcpy(data + 4 + text.length(), &zero, 1);
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (!((PlayerInfo*)(currentPeer->data))->radio)
										continue;

									p.CreatePacket(currentPeer);

									ENetPacket* packet2 = enet_packet_create(data,
										5 + text.length(),
										ENET_PACKET_FLAG_RELIABLE);

									enet_peer_send(currentPeer, 0, packet2);

									//enet_host_flush(server);
								}
								delete[] data;
							}
							else if (str.substr(0, 6) == "/radio") {
								gamepacket_t p;
								if (((PlayerInfo*)(peer->data))->radio) {
									p.Insert("OnConsoleMessage");
									p.Insert("You won't see broadcasts anymore.");
									((PlayerInfo*)(peer->data))->radio = false;
								}
								else {
									p.Insert("OnConsoleMessage");
									p.Insert("You will now see broadcasts again.");
									((PlayerInfo*)(peer->data))->radio = true;
								}
								p.CreatePacket(peer);
							}
							else if (str.substr(0, 7) == "/color ")
							{
								((PlayerInfo*)(peer->data))->skinColor = atoi(str.substr(6, cch.length() - 6 - 1).c_str());
								sendClothes(peer);
							}
							else if (str.substr(0, 4) == "/who")
							{
								sendWho(peer);
							}
						}
						if (str.length() && str[0] == '/')
						{
							sendAction(peer, ((PlayerInfo*)(peer->data))->netID, str);
						}
						else if (str.length() > 0)
						{
							if (((PlayerInfo*)(peer->data))->taped == false) {
								sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, str);
							}
							else {
								// Is duct-taped
								sendChatMessage(peer, ((PlayerInfo*)(peer->data))->netID, randomDuctTapeMessage(str.length()));
							}
						}
					}
					if (!((PlayerInfo*)(event.peer->data))->isIn)
					{
						if (itemdathash == 0) {
							enet_peer_disconnect_later(peer, 0);
						}
						std::stringstream ss(GetTextPointerFromPacket(event.packet));
						std::string to;
						while (std::getline(ss, to, '\n')) {
							string id = to.substr(0, to.find("|"));
							string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
							if (peer == NULL || peer == nullptr) {
								break;
							}
							if (id == "tankIDName") {
								if (act.length() > 25) break;
								((PlayerInfo*)(event.peer->data))->tankIDName = act;
								((PlayerInfo*)(event.peer->data))->haveGrowId = true;
							}
							else if (id == "tankIDPass") {
								((PlayerInfo*)(event.peer->data))->tankIDPass = act;
							}
							else if (id == "requestedName") {
								((PlayerInfo*)(event.peer->data))->requestedName = act;
							}
							else if (id == "country") {
								((PlayerInfo*)(event.peer->data))->country = act;
							}
							else if (id == "game_version") {
								((PlayerInfo*)(event.peer->data))->gameversion = act;
							}
							else if (id == "rid") {
								((PlayerInfo*)(event.peer->data))->rid = act;
								if (act.length() < 32) break;
								if (act.length() > 36) break;
								if (act == "01405CAC015A0E02063E7F4810290291") break;
							}
							else if (id == "wk") {
								bool valid = true;
								try {
									if (act.substr(0, 4) == "NONE" || act.substr(1, 4) == "NONE" || act.substr(3, 4) == "NONE") valid = false;
								}
								catch (const std::out_of_range& e) {
									valid = false;
									break;
								}
								if (valid) {
									((PlayerInfo*)(event.peer->data))->sid = act;
									if (act.length() < 32) break;
									if (act.length() > 36) break;
								}
							}
							else if (id == "zf") {
								((PlayerInfo*)(event.peer->data))->zf = act;
							}
							/*else if (id == "meta") {
								if (act != "Growtopia-50021") enet_peer_disconnect_now(peer, 0);
								((PlayerInfo*)(event.peer->data))->metaip = act;
							}*/
							else if (id == "hash2") {
								if (act.length() != 0) {
									if (act.length() > 16) break;
								}
							}
							else if (id == "platformID") {
								if (act.length() == 0) break;
								((PlayerInfo*)(event.peer->data))->platformID = act;
							}
							else if (id == "player_age") {
								((PlayerInfo*)(event.peer->data))->player_age = act;
							}
							else if (id == "fhash") {
								((PlayerInfo*)(event.peer->data))->fhash = act;
							}
							else if (id == "mac") {
								((PlayerInfo*)(event.peer->data))->mac = act;
								if (act.length() < 16) break;
								if (act.length() > 20) break;
							}
							else if (id == "hash") {
								if (act.length() != 0) {
									if (act.length() < 6) break;
									if (act.length() > 16) break;
								}
							}
							else if (id == "aid") {
								((PlayerInfo*)(event.peer->data))->aid = act;
							}
							else if (id == "houstonProductID") {
								((PlayerInfo*)(event.peer->data))->hpid = act;
							}
							else if (id == "gid") {
								((PlayerInfo*)(event.peer->data))->gid = act;
							}
							else if (id == "vid") {
								((PlayerInfo*)(event.peer->data))->vid = act;
							}
							else if (id == "f") {
								((PlayerInfo*)(event.peer->data))->f = act;
							}
							else if (id == "fz") {
								((PlayerInfo*)(event.peer->data))->fz = act;
							}
							else if (id == "lmode") {
								((PlayerInfo*)(event.peer->data))->lmode = act;
							}
							else if (id == "user") {
								((PlayerInfo*)(event.peer->data))->user = act;
							}
							else if (id == "token") {
								((PlayerInfo*)(event.peer->data))->token = act;
							}
							else if (id == "GDPR") {
								((PlayerInfo*)(event.peer->data))->gdpr = act;
							}
							else if (id == "deviceVersion") {
								((PlayerInfo*)(event.peer->data))->deviceversion = act;
							}
							else if (id == "doorID") {
								((PlayerInfo*)(event.peer->data))->doorID = act;
							}
						}
						if (((PlayerInfo*)(event.peer->data))->mac == "" || ((PlayerInfo*)(event.peer->data))->rid == "" || ((PlayerInfo*)(event.peer->data))->player_age == "") {
							enet_peer_disconnect_later(peer, 0);
						}

						GamePacket p12 = packetEnd(appendInt(appendInt(appendInt(appendString(createPacket(), "OnOverrideGDPRFromServer"), 68), 1), 0));
						ENetPacket* packet12 = enet_packet_create(p12.data, p12.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet12);
						delete p12.data;
						GamePacket p33 = packetEnd(appendInt(appendInt(appendString(createPacket(), "OnSetRoleSkinsAndTitles"), 000000), 000000));
						ENetPacket* packet33 = enet_packet_create(p33.data, p33.len, ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet33);
						delete p33.data;
						gamepacket_t p;
						p.Insert("OnSuperMainStartAcceptLogonHrdxs47254722215a");
						p.Insert(itemdathash);
						p.Insert("ubistatic-a.akamaihd.net");
						p.Insert(configCDN);
						p.Insert("cc.cz.madkite.freedom org.aqua.gg idv.aqua.bulldog com.cih.gamecih2 com.cih.gamecih com.cih.game_cih cn.maocai.gamekiller com.gmd.speedtime org.dax.attack com.x0.strai.frep com.x0.strai.free org.cheatengine.cegui org.sbtools.gamehack com.skgames.traffikrider org.sbtoods.gamehaca com.skype.ralder org.cheatengine.cegui.xx.multi1458919170111 com.prohiro.macro me.autotouch.autotouch com.cygery.repetitouch.free com.cygery.repetitouch.pro com.proziro.zacro com.slash.gamebuster");
						p.Insert("proto=135|choosemusic=audio/mp3/theme2.mp3|active_holiday=0|wing_week_day=0|server_tick=49302888|clash_active=0|drop_lavacheck_faster=1|isPayingUser=0|usingStoreNavigation=1|enableInventoryTab=1|bigBackpack=1|");
						p.CreatePacket(peer);
						gamepacket_t a;
						a.Insert("OnOverrideGDPRFromServer");
						a.Insert(26);
						a.Insert(1);
						a.Insert(0);
						a.Insert(1);
						a.CreatePacket(peer);
						gamepacket_t b;
						b.Insert("OnSetRoleSkinsAndTitles");
						b.Insert(000000);
						b.Insert(000000);
						b.CreatePacket(peer);
						if (!((PlayerInfo*)(event.peer->data))->haveGrowId)
						{
							((PlayerInfo*)(event.peer->data))->hasLogon = true;
							((PlayerInfo*)(event.peer->data))->rawName = "";
							string guestID;
							string addresshost = to_string(peer->address.host);
							guestID = addresshost;
							guestID.erase(3, addresshost.length());
							((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->requestedName.substr(0, ((PlayerInfo*)(event.peer->data))->requestedName.length() > 15 ? 15 : ((PlayerInfo*)(event.peer->data))->requestedName.length()) + "_" + guestID + "``");
						}
						else {
							((PlayerInfo*)(event.peer->data))->rawName = PlayerDB::getProperName(((PlayerInfo*)(event.peer->data))->tankIDName);
#ifdef REGISTRATION
							int logStatus = PlayerDB::playerLogin(peer, ((PlayerInfo*)(event.peer->data))->rawName, ((PlayerInfo*)(event.peer->data))->tankIDPass);
							if (logStatus == 1) {
								string x = ((PlayerInfo*)(event.peer->data))->tankIDName;
								if (x.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos)
								{
									Player::OnConsoleMessage(peer, "`4Unable to log on `oThat `wGrowID`o doesn't seem valid, or the password is wrong. If you don't have one, click`w cancel`o, un-check `w'i have a GrowlD'`o, then click `wConnect`o.");
									SendPacket(3, "action|logon_fail\n", peer);
									enet_peer_disconnect_later(peer, 0);
								}
								else if (((PlayerInfo*)(peer->data))->banned == true) {
									Player::OnConsoleMessage(peer, "`5Sorry, but this account (`w" + ((PlayerInfo*)(event.peer->data))->tankIDName + "`5) has been suspended.");
									SendPacket(3, "action|logon_fail\n", peer);
									enet_peer_disconnect_later(peer, 0);
								}
								else if (((PlayerInfo*)(peer->data))->cursed == true) {
									Player::OnConsoleMessage(peer, "`4You have been cursed, dwell in hell");
								}
								else if (GlobalMaintenance) {
									SendPacket(3, "action|logon_fail\n", peer);
									packet::consolemessage(peer, "`5Server is under maintenance. Comeback later.``");
									enet_peer_disconnect_later(peer, 0);
								}
								else {
									((PlayerInfo*)(event.peer->data))->displayName = ((PlayerInfo*)(event.peer->data))->tankIDName;
								}
							}
							else {
								Player::OnConsoleMessage(peer, "`4Unable to log on `oThat `wGrowID`o doesn't seem valid, or the password is wrong. If you don't have one, click`w cancel`o, un-check `w'i have a GrowlD'`o, then click `wConnect`o.");
								enet_peer_disconnect_later(peer, 0);
							}
#else

							((PlayerInfo*)(event.peer->data))->displayName = PlayerDB::fixColors(((PlayerInfo*)(event.peer->data))->tankIDName.substr(0, ((PlayerInfo*)(event.peer->data))->tankIDName.length() > 18 ? 18 : ((PlayerInfo*)(event.peer->data))->tankIDName.length()));
							if (((PlayerInfo*)(event.peer->data))->displayName.length() < 3) ((PlayerInfo*)(event.peer->data))->displayName = "Person that doesn't know how the name looks!";
#endif
						}
						for (char c : ((PlayerInfo*)(event.peer->data))->displayName) if (c < 0x20 || c>0x7A) ((PlayerInfo*)(event.peer->data))->displayName = "Bad characters in name, remove them!";

						if (((PlayerInfo*)(event.peer->data))->country.length() > 4)
						{
							((PlayerInfo*)(event.peer->data))->country = "us";
						}
						if (((PlayerInfo*)(event.peer->data))->adminLevel > 1)
						{
							((PlayerInfo*)(event.peer->data))->country = "us";
						}

						//Disarankan Kode Bluename Dibawah.
						if (((PlayerInfo*)(event.peer->data))->haveBluename == true)
						{
							((PlayerInfo*)(event.peer->data))->country = ((PlayerInfo*)(event.peer->data))->country + "|maxLevel";
						}
						gamepacket_t p2;
						p2.Insert("SetHasGrowID");
						p2.Insert(((PlayerInfo*)(event.peer->data))->haveGrowId);
						p2.Insert(((PlayerInfo*)(peer->data))->tankIDName);
						p2.Insert(((PlayerInfo*)(peer->data))->tankIDPass);
						p2.CreatePacket(peer);
					}
					string pStr = GetTextPointerFromPacket(event.packet);
					//if (strcmp(GetTextPointerFromPacket(event.packet), "action|enter_game\n") == 0 && !((PlayerInfo*)(event.peer->data))->isIn)
					if (pStr.substr(0, 17) == "action|enter_game" && !((PlayerInfo*)(event.peer->data))->isIn)
					{
						
#ifdef TOTAL_LOG
						cout << "And we are in!" << endl;
#endif

						UpdateOnline();

						((PlayerInfo*)(event.peer->data))->isIn = true;
						sendWorldOffers(peer);
						savejson(peer);
						savePunishment(peer);
						saveOptions(peer);
						gamepacket_t p;
						p.Insert("OnSetBux");
						p.Insert(((PlayerInfo*)(peer->data))->gem);
						p.CreatePacket(peer);
						GamePacket p2ssw = packetEnd(appendString(appendInt(appendString(createPacket(), "OnEmoticonDataChanged"), 201560520), "(wl)|ā|1&(yes)|Ă|1&(no)|ă|1&(love)|Ą|1&(oops)|ą|1&(shy)|Ć|1&(wink)|ć|1&(tongue)|Ĉ|1&(agree)|ĉ|1&(sleep)|Ċ|1&(punch)|ċ|1&(music)|Č|1&(build)|č|1&(megaphone)|Ď|1&(sigh)|ď|1&(mad)|Đ|1&(wow)|đ|1&(dance)|Ē|1&(see-no-evil)|ē|1&(bheart)|Ĕ|1&(heart)|ĕ|1&(grow)|Ė|1&(gems)|ė|1&(kiss)|Ę|1&(gtoken)|ę|1&(lol)|Ě|1&(smile)|Ā|1&(cool)|Ĝ|1&(cry)|ĝ|1&(vend)|Ğ|1&(bunny)|ě|1&(cactus)|ğ|1&(pine)|Ĥ|1&(peace)|ģ|1&(terror)|ġ|1&(troll)|Ģ|1&(evil)|Ģ|1&(fireworks)|Ħ|1&(football)|ĥ|1&(alien)|ħ|1&(party)|Ĩ|1&(pizza)|ĩ|1&(clap)|Ī|1&(song)|ī|1&(ghost)|Ĭ|1&(nuke)|ĭ|1&(halo)|Į|1&(turkey)|į|1&(gift)|İ|1&(cake)|ı|1&(heartarrow)|Ĳ|1&(lucky)|ĳ|1&(shamrock)|Ĵ|1&(grin)|ĵ|1&(ill)|Ķ|1&"));
						ENetPacket* packet2ssw = enet_packet_create(p2ssw.data,
							p2ssw.len,
							ENET_PACKET_FLAG_RELIABLE);
						enet_peer_send(peer, 0, packet2ssw);
						delete p2ssw.data;
						if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
							if (((PlayerInfo*)(peer->data))->AAP != "") {
								((PlayerInfo*)(peer->data))->AAPfirst = true;
								string AAPdialog = (
									"set_default_color|`o\n\nadd_label_with_icon|big|`wAdvanced Account Protection``|left|242|\n\nadd_spacer|small|\nadd_smalltext|`wThis account is protected, if you are owner of this account please enter the verification code you created before.|\nadd_text_input|AAPcode|Verification code:||5|\nend_dialog|aaprequest|Cancel|`2Verify|\n"
									);
								Player::OnDialogRequest(peer, AAPdialog);

							}
							string Ccode = "";
							string Ccode2 = "`o";
							if (((PlayerInfo*)(peer->data))->adminLevel == 5) {//dev
								Ccode = "`6@";
								Ccode2 = "`6@";
								((ServerPermissions*)(peer->data))->freeItems = true;
							}
							else if (((PlayerInfo*)(peer->data))->adminLevel == 4) {//co
								Ccode = "`e@";
								Ccode2 = "`e@";
							}
							else if (((PlayerInfo*)(peer->data))->adminLevel == 3) {//admin
								Ccode = "`4@";
								Ccode2 = "`4@";
							}
							else if (((PlayerInfo*)(peer->data))->adminLevel == 2) {//mod
								Ccode = "`#@";
								Ccode2 = "`#@";
							}
							else if (((PlayerInfo*)(peer->data))->adminLevel == 1) {//vip
								Ccode = "`3@";
								Ccode2 = "`3@";
							}
							else {
								Ccode = "`w";
								Ccode2 = "`o";
							}
							if (((PlayerInfo*)(peer->data))->haveSuperSupporterName == true) {
								gamepacket_t s(0);
								s.Insert("OnSetBux");
								s.Insert(((PlayerInfo*)(peer->data))->gem);
								s.Insert(1);
								s.Insert(1);
								s.Insert("x: 58753.000000 y: 1.000000 z: 0.000000");
								s.CreatePacket(peer);
							}
							((PlayerInfo*)(peer->data))->displayName = Ccode + ((PlayerInfo*)(peer->data))->tankIDName;
							((PlayerInfo*)(peer->data))->displayNameBackup = Ccode + ((PlayerInfo*)(peer->data))->tankIDName;
							if (((ServerPermissions*)(peer->data))->freeItems == true) {
								Player::OnConsoleMessage(peer, "`2Server Settings`o: `wNow you can take all items for free by doing /find [item]")
									;
							}
							if (((PlayerInfo*)(peer->data))->haveBluename == true) {

							}
							std::ifstream ifff("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
							if (ifff.fail()) {
								std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
								if (!oo.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								json items;
								json jjall = json::array();
								json jj;
								jj["position"] = 1;
								jj["itemid"] = 18;
								jj["count"] = 1;
								jjall.push_back(jj);
								jj["position"] = 2;
								jj["itemid"] = 32;
								jj["count"] = 1;
								jjall.push_back(jj);
								for (int i = 2; i < 250; i++)
								{
									jj["position"] = i + 1;
									jj["itemid"] = 0;
									jj["count"] = 0;
									jjall.push_back(jj);
								}
								items["items"] = jjall;
								oo << items << std::endl;
								ifff.close();
								Player::OnConsoleMessage(peer, "`oInventory created!");
								enet_peer_disconnect_now(peer, 0);
								continue;
							}
							if (ifff.is_open()) {
							}
							json j;
							ifff >> j; //load

							if (j["items"][0]["itemid"] != 18 || j["items"][1]["itemid"] != 32)
							{
								j["items"][0]["itemid"] = 18;
								j["items"][1]["itemid"] = 32;

								j["items"][0]["count"] = 1;
								j["items"][1]["count"] = 1;

								std::ofstream oo("playersInventory/" + ((PlayerInfo*)(peer->data))->rawName + ".json");
								if (!oo.is_open()) {
									cout << GetLastError() << endl;
									_getch();
								}
								oo << j << std::endl;
							}
							PlayerInventory inventory = ((PlayerInfo*)(peer->data))->inventory;
							{
								InventoryItem item;
								for (int i = 0; i < inventory.inventorySize; i++)
								{
									int itemid = j["items"][i]["itemid"];
									int quantity = j["items"][i]["count"];
									if (itemid != 0 && quantity != 0)
									{
										item.itemCount = quantity;
										item.itemID = itemid;
										inventory.items.push_back(item);
										sendInventory(peer, inventory);
									}
								}
							}
							((PlayerInfo*)(event.peer->data))->inventory = inventory;
						}
						packet::consolemessage(peer, "`oWelcome back, `w" + ((PlayerInfo*)(event.peer->data))->displayName + "`o.``");
						
						Sleep(5000);
						packet::consolemessage(peer, "`oProject Cold By `wTime");

						{
							//GamePacket p = packetEnd(appendString(appendString(createPacket(), "OnDialogRequest"), "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\n\nadd_image_button|banner|interface/large/news_banner.rttex|noflags|||\n\nadd_spacer|small|\n\nadd_textbox|`wSeptember 10:`` `5Surgery Stars end!``|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Hello Growtopians,|left|\n\nadd_spacer|small|\n\n\n\nadd_textbox|Surgery Stars is over! We hope you enjoyed it and claimed all your well-earned Summer Tokens!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|As we announced earlier, this month we are releasing the feature update a bit later, as we're working on something really cool for the monthly update and we're convinced that the wait will be worth it!|left|\n\nadd_spacer|small|\n\nadd_textbox|Check the Forum here for more information!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wSeptember Updates Delay``|noflags|https://www.growtopiagame.com/forums/showthread.php?510657-September-Update-Delay&p=3747656|Open September Update Delay Announcement?|0|0|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|Also, we're glad to invite you to take part in our official Growtopia survey!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wTake Survey!``|noflags|https://ubisoft.ca1.qualtrics.com/jfe/form/SV_1UrCEhjMO7TKXpr?GID=26674|Open the browser to take the survey?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Click on the button above and complete the survey to contribute your opinion to the game and make Growtopia even better! Thanks in advance for taking the time, we're looking forward to reading your feedback!|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\nadd_textbox|And for those who missed PAW, we made a special video sneak peek from the latest PAW fashion show, check it out on our official YouTube channel! Yay!|left|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wPAW 2018 Fashion Show``|noflags|https://www.youtube.com/watch?v=5i0IcqwD3MI&feature=youtu.be|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_spacer|small|\n\nadd_textbox|Lastly, check out other September updates:|left|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|IOTM: The Sorcerer's Tunic of Mystery|left|24|\n\nadd_label_with_icon|small|New Legendary Summer Clash Branch|left|24|\n\nadd_spacer|small|\n\nadd_textbox|`$- The Growtopia Team``|left|\n\nadd_spacer|small|\n\nadd_spacer|small|\n\n\n\n\n\nadd_url_button|comment|`wOfficial YouTube Channel``|noflags|https://www.youtube.com/c/GrowtopiaOfficial|Open the Growtopia YouTube channel for videos and tutorials?|0|0|\n\nadd_url_button|comment|`wSeptember's IOTM: `8Sorcerer's Tunic of Mystery!````|noflags|https://www.growtopiagame.com/forums/showthread.php?450065-Item-of-the-Month&p=3392991&viewfull=1#post3392991|Open the Growtopia website to see item of the month info?|0|0|\n\nadd_spacer|small|\n\nadd_label_with_icon|small|`4WARNING:`` `5Drop games/trust tests`` and betting games (like `5Casinos``) are not allowed and will result in a ban!|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` Using any kind of `5hacked client``, `5spamming/text pasting``, or `5bots`` (even with an alt) will likely result in losing `5ALL`` your accounts. Seriously.|left|24|\n\nadd_label_with_icon|small|`4WARNING:`` `5NEVER enter your GT password on a website (fake moderator apps, free gemz, etc) - it doesn't work and you'll lose all your stuff!|left|24|\n\nadd_spacer|small|\n\nadd_url_button|comment|`wGrowtopia on Facebook``|noflags|http://growtopiagame.com/facebook|Open the Growtopia Facebook page in your browser?|0|0|\n\nadd_spacer|small|\n\nadd_button|rules|`wHelp - Rules - Privacy Policy``|noflags|0|0|\n\n\nadd_quick_exit|\n\nadd_spacer|small|\nadd_url_button|comment|`wVisit Growtopia Forums``|noflags|http://www.growtopiagame.com/forums|Visit the Growtopia forums?|0|0|\nadd_spacer|small|\nadd_url_button||`wWOTD: `1THELOSTGOLD`` by `#iWasToD````|NOFLAGS|OPENWORLD|THELOSTGOLD|0|0|\nadd_spacer|small|\nadd_url_button||`wVOTW: `1Yodeling Kid - Growtopia Animation``|NOFLAGS|https://www.youtube.com/watch?v=UMoGmnFvc58|Watch 'Yodeling Kid - Growtopia Animation' by HyerS on YouTube?|0|0|\nend_dialog|gazette||OK|"));
							sendnews(peer);
						}
					}
					if (strcmp(GetTextPointerFromPacket(event.packet), "action|refresh_item_data\n") == 0) {
						if (itemsDat != nullptr) {
							ENetPacket* packet = enet_packet_create(itemsDat, itemsDatSize + 60, ENET_PACKET_FLAG_RELIABLE);
							enet_peer_send(peer, 0, packet);
						}
					}
					break;
				}
				default:
					cout << "Unknown packet type " << messageType << endl;
					enet_peer_reset(peer);
					break;
				case 3:
				{
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					std::stringstream ss(GetTextPointerFromPacket(event.packet));
					std::string to;
					bool isJoinReq = false;
					bool isValidateReq = false, isWBreq = false;
					while (std::getline(ss, to, '\n')) {
						string id = to.substr(0, to.find("|"));
						string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
						if (id == "name" && isJoinReq)
						{
#ifdef TOTAL_LOG
							cout << "Entering some world..." << endl;
#endif
							if (!((PlayerInfo*)(peer->data))->hasLogon) break;
							try {
								if (act.length() > 30) {
									packet::consolemessage(peer, "`4Sorry, but world names with more than 30 characters are not allowed!");
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									gamepacket_t p;
									p.Insert("OnFailedToEnterWorld");
									p.Insert(1);
									p.CreatePacket(peer);

								}
								else {
									joinWorld(peer, act);
									if (((PlayerInfo*)(peer->data))->taped) {
										((PlayerInfo*)(peer->data))->isDuctaped = true;
										sendState(peer);
									}
								}
							}
							catch (int e) {
								if (e == 1) {
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									gamepacket_t p;
									p.Insert("OnFailedToEnterWorld");
									p.Insert(1);
									p.CreatePacket(peer);
									packet::consolemessage(peer, "You have exited the world.");
								}
								else if (e == 2) {
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									gamepacket_t p;
									p.Insert("OnFailedToEnterWorld");
									p.Insert(1);
									p.CreatePacket(peer);
									packet::consolemessage(peer, "You have entered bad characters in the world name!");
								}
								else if (e == 3) {
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									gamepacket_t p;
									p.Insert("OnFailedToEnterWorld");
									p.Insert(1);
									p.CreatePacket(peer);
									packet::consolemessage(peer, "Exit from what? Click back if you're done playing.");
								}
								else {
									((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
									gamepacket_t p;
									p.Insert("OnFailedToEnterWorld");
									p.Insert(1);
									p.CreatePacket(peer);
									packet::consolemessage(peer, "I know this menu is magical and all, but it has its limitations! You can't visit this world!");
								}
							}
						}
						else if (id == "name" && isValidateReq) {
							if (act.length() < 32) {
								isValidateReq = false;
								string id = "0";
								std::ifstream ifs("worlds/_" + act + ".json");
								if (ifs.is_open()) {
									id = "0";
								}
								if (!ifs.is_open()) {
									id = "1";
								}
								if (act.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos)
								{
									SendPacket(3, "action|world_validated\navailable|-1\nworld_name|" + act, peer);
								}
								else {
									SendPacket(3, "action|world_validated\navailable|" + id + "\nworld_name|" + act, peer);
								}
							}
						}
						else if (id == "name" && isWBreq) {
							if (act == "_catselect_") {
								string selectMenu =
									"add_button|Random|_0|0.8|3529161471|"
									"\nadd_button|Your Worlds|_myworlds|0.8|3529161471|"
									"\nadd_button|Favorite|_myfavorite|0.8|3529161471|"
									"\nadd_button|Adventure|_1|0.8|3529161471|"
									"\nadd_button|Art|_2|0.8|3529161471|"
									"\nadd_button|Farm|_3|0.8|3529161471|"
									"\nadd_button|Game|_4|0.8|3529161471|"
									"\nadd_button|Guild|_13|0.8|3529161471|"
									"\nadd_button|Information|_5|0.8|3529161471|"
									"\nadd_button|Music|_15|0.8|3529161471|"
									"\nadd_button|Parkour|_6|0.8|3529161471|"
									"\nadd_button|Puzzle|_14|0.8|3529161471|"
									"\nadd_button|Roleplay|_7|0.8|3529161471|"
									"\nadd_button|Shop|_8|0.8|3529161471|"
									"\nadd_button|Social|_9|0.8|3529161471|"
									"\nadd_button|Storage|_10|0.8|3529161471|"
									"\nadd_button|Story|_11|0.8|3529161471|"
									"\nadd_button|Trade|_12|0.8|3529161471|"
									;
								packet::requestworldselectmenu(peer, selectMenu);
							}
							if (act == "_0") {
								sendWorldOffers(peer);
							}
							else if (act != "_0") Player::OnConsoleMessage(peer, "Soon!");
						}
						if (id == "action")
						{
							if (act == "validate_world") {
								isValidateReq = true;
							}
							if (act == "world_button") {
								isWBreq = true;
							}
							if (act == "join_request")
							{
								if (((PlayerInfo*)(peer->data))->AAPfirst == true) {
									string AAPdialog = (
										"set_default_color|`o\n\nadd_label_with_icon|big|`wAdvanced Account Protection``|left|242|\n\nadd_spacer|small|\nadd_smallbox|`wThis account is protected, if you are owner of this account please enter the verification code you created before.|\nadd_text_input|AAPcode|Verification code:||5|\nend_dialog|aaprequest|Cancel|`2Verify|\n"
										);
									Player::OnDialogRequest(peer, AAPdialog);
									Player::OnFailedToEnterWorld(peer);
									continue;
								}
								else {
									isJoinReq = true;
								}
							}
							if (act == "quit_to_exit")
							{
								((PlayerInfo*)(peer->data))->bypass_underscore = false;
								//sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
								((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
								savejson(peer);
								sendWorldOffers(peer);
							}
							if (act == "quit")
							{
								savejson(peer);
								enet_peer_disconnect_later(peer, 0);
							}
						}
					}
					break;
				}
				case 4:
				{
					{
						if (!world) continue;
						if (((PlayerInfo*)(peer->data))->currentWorld == "EXIT") continue;
						BYTE* tankUpdatePacket = GetStructPointerFromTankPacket(event.packet);
						if (tankUpdatePacket)
						{
							PlayerMoving* pMov = unpackPlayerMoving(tankUpdatePacket);
							if (int(pMov->x) >= 1 && int(pMov->y) >= 1) {
								//Anti Cheat Noclip
								
								int tile = world->items[int(pMov->x / 32) + (int(pMov->y / 32) * world->width)].foreground;
								if (tile != 0 && getItemDef(tile).blockType != BlockTypes::BACKGROUND && getItemDef(tile).blockType != BlockTypes::CHECKPOINT && getItemDef(tile).blockType != BlockTypes::DOOR && getItemDef(tile).blockType != BlockTypes::MAIN_DOOR && getItemDef(tile).blockType != BlockTypes::SIGN && getItemDef(tile).blockType != BlockTypes::PLATFORM && getItemDef(tile).editableType != 1 && getItemDef(tile).editableType != 3 && getItemDef(tile).editableType != 20 && getItemDef(tile).spreadType != 3 && tile != 192) {
									gamepacket_t s(0, ((PlayerInfo*)(peer->data))->netID);
									s.Insert("OnSetPos");
									s.Insert(((PlayerInfo*)(peer->data))->x, ((PlayerInfo*)(peer->data))->y);
									s.CreatePacket(peer);
									continue;

								}
								
							}
							switch (pMov->packetType)
							{
							case 0:

								((PlayerInfo*)(event.peer->data))->x = pMov->x;
								((PlayerInfo*)(event.peer->data))->y = pMov->y;
								((PlayerInfo*)(event.peer->data))->isRotatedLeft = pMov->characterState & 0x10;
								sendPData(peer, pMov);
								if (((PlayerInfo*)(peer->data))->joinClothesUpdated == false)
								{
									ENetPeer* currentPeer;
									for (currentPeer = server->peers;
										currentPeer < &server->peers[server->peerCount];
										++currentPeer)
									{
										if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
											continue;
										if (isHere(peer, currentPeer))
										{
											gamepacket_t s(0);
											s.Insert("OnCountryState");
											s.Insert(((PlayerInfo*)(peer->data))->country);
											s.CreatePacket(peer);
											s.CreatePacket(currentPeer);

											gamepacket_t h(0);
											h.Insert("OnFlagMay2019");
											h.Insert(256);
											h.CreatePacket(peer);
											h.CreatePacket(currentPeer);
											sendClothes(peer);
											sendClothes(currentPeer);
											sendState(peer);
											sendState(currentPeer);
										}
									}
									((PlayerInfo*)(peer->data))->joinClothesUpdated = true;

								}
								break;

							default:
								break;
							}
							PlayerMoving* data2 = unpackPlayerMoving(tankUpdatePacket);
							//Player::OnConsoleMessage(peer, to_string(data2->packetType));
							if (data2->packetType == 0) {
								if (((PlayerInfo*)(peer->data))->sendToWorld != "") {
									joinWorld(peer, ((PlayerInfo*)(peer->data))->sendToWorld);
									((PlayerInfo*)(peer->data))->sendToWorld = "";

									continue;
									break;
								}
								ENetPeer* currentPeer;

								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (((PlayerInfo*)(peer->data))->fastPunch == false) {
										if (((PlayerInfo*)(peer->data))->attempt <= 12) {
											sendState(peer);
											sendState(currentPeer);
											if (((PlayerInfo*)(peer->data))->haveGrowId == true || ((PlayerInfo*)(currentPeer->data))->haveGrowId == true) {
												sendClothes(peer);
												sendClothes(currentPeer);
											}
											((PlayerInfo*)(peer->data))->attempt += 1;
										}
									}
									else {
										if (((PlayerInfo*)(peer->data))->attempt <= 12) {
											sendState(peer);
											sendState(currentPeer);
											if (((PlayerInfo*)(peer->data))->haveGrowId == true || ((PlayerInfo*)(currentPeer->data))->haveGrowId == true) {
												sendClothes(peer);
												sendClothes(currentPeer);
											}
											((PlayerInfo*)(peer->data))->attempt += 1;
										}
										if (((PlayerInfo*)(peer->data))->haveGrowId == true || ((PlayerInfo*)(currentPeer->data))->haveGrowId == true) {
											sendClothes(peer);
											sendClothes(currentPeer);
										}
									}
									if (((PlayerInfo*)(peer->data))->attempt >= 10 && ((PlayerInfo*)(peer->data))->fastPunch == false && world->owner != "" && ((PlayerInfo*)(peer->data))->haveGrowId == true) {
										using namespace std::chrono;
										if (((PlayerInfo*)(peer->data))->delay_SaveBuilding == 0) {
											((PlayerInfo*)(peer->data))->delay_SaveBuilding = 500; //Nerf (100->500)
											saveCurrentWorld(peer, ((PlayerInfo*)(peer->data))->currentWorld);
										}
										if (((PlayerInfo*)(peer->data))->delay_SaveBuilding != 0) {
											((PlayerInfo*)(peer->data))->delay_SaveBuilding -= 1;
											continue;
										}
									}
								}
							}

							if (data2->packetType == 22) {
								PlayerMoving data;
								data.packetType = 0x0;
								data.characterState = data2->characterState; // animation
								data.x = ((PlayerInfo*)(peer->data))->x;
								data.y = ((PlayerInfo*)(peer->data))->y;
								data.punchX = data2->punchX;
								data.punchY = data2->punchY;
								data.XSpeed = data2->XSpeed;
								data.YSpeed = data2->YSpeed;
								data.netID = -1;
								data.plantingTree = data2->plantingTree;
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
							} //KEEP ALIVE (LIMITED).

							if (data2->packetType == 11)
							{
								sendCollect(peer, ((PlayerInfo*)(peer->data))->netID, data2->plantingTree);
							}
							if (data2->packetType == 7)
							{
								int x = pMov->punchX;
								int y = pMov->punchY;
								int tile = world->items[x + (y * world->width)].foreground;
								int netID = ((PlayerInfo*)(peer->data))->netID;
								WorldInfo info = worldDB.get(peer, ((PlayerInfo*)(peer->data))->currentWorld);
								if (data2->punchX < world->width && data2->punchY < world->height)
									if (getItemDef(world->items[data2->punchX + (data2->punchY * world->width)].foreground).blockType == BlockTypes::MAIN_DOOR) {
										if (((PlayerInfo*)(peer->data))->haveGrowId == true) {
											///sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
											((PlayerInfo*)(peer->data))->currentWorld = "EXIT";
											savejson(peer);
											sendWorldOffers(peer);
										}
										else {
											Player::OnAddNotification(peer, "`wCreate GrowID First", "", "loldldel");
											Player::OnZoomCamera(peer, 10000, 1000);
											Player::OnSetFreezeState(peer, 0, netID);
										}
									}
									else if (getItemDef(tile).blockType == BlockTypes::CHECKPOINT) {
										((PlayerInfo*)(peer->data))->respawnX = x * 32;
										((PlayerInfo*)(peer->data))->respawnY = y * 32;
										Player::SetRespawnPos(peer, x, (world->width * y), netID);
									}
									else {
										if (getItemDef(tile).blockType == BlockTypes::PORTAL) {
											Player::OnPlayPositioned(peer, "audio/teleport.wav", ((PlayerInfo*)(peer->data))->netID, false, NULL);
										}
										else {
											Player::OnPlayPositioned(peer, "audio/door_open.wav", ((PlayerInfo*)(peer->data))->netID, false, NULL);
										}
										int x = 3040;
										int y = 736;
										for (int j = 0; j < info.width * info.height; j++)
										{
											if (info.items[j].foreground == tile) {
												x = (j % info.width) * 32;
												y = (j / info.width) * 32;
											}
										}
										Player::OnSetPos(peer, ((PlayerInfo*)(peer->data))->netID, x, y, 0);
										Player::OnZoomCamera(peer, 10000, 1000);
										Player::OnSetFreezeState(peer, 0, netID);
									}
							}
							if (data2->packetType == 10)
							{
								//cout << pMov->x << ";" << pMov->y << ";" << pMov->plantingTree << ";" << pMov->punchX << ";" << pMov->punchY << ";" << pMov->characterState << endl;
								ItemDefinition def;
								try {
									def = getItemDef(pMov->plantingTree);
								}
								catch (int e) {
									goto END_CLOTHSETTER_FORCE;
								}

								switch (def.clothType) {
								case 0:
									if (((PlayerInfo*)(event.peer->data))->cloth0 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth0 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth0 = pMov->plantingTree;
									break;
								case 1:
									if (((PlayerInfo*)(event.peer->data))->cloth1 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth1 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth1 = pMov->plantingTree;
									break;
								case 2:
									if (((PlayerInfo*)(event.peer->data))->cloth2 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth2 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth2 = pMov->plantingTree;
									break;
								case 3:
									if (((PlayerInfo*)(event.peer->data))->cloth3 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth3 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth3 = pMov->plantingTree;
									break;
								case 4:
									if (((PlayerInfo*)(event.peer->data))->cloth4 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth4 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth4 = pMov->plantingTree;
									break;
								case 5:
									if (((PlayerInfo*)(event.peer->data))->cloth5 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth5 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth5 = pMov->plantingTree;
									break;
								case 6:
									if (((PlayerInfo*)(event.peer->data))->cloth6 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth6 = 0;
										((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
										sendState(peer);
										break;
									}
									{
										((PlayerInfo*)(event.peer->data))->cloth6 = pMov->plantingTree;
										int item = pMov->plantingTree;
										if (item == 156 || item == 362 || item == 678 || item == 736 || item == 818 || item == 1206 || item == 1460 || item == 1550 || item == 1574 || item == 1668 || item == 1672 || item == 1674 || item == 1784 || item == 1824 || item == 1936 || item == 1938 || item == 1970 || item == 2254 || item == 2256 || item == 2258 || item == 2260 || item == 2262 || item == 2264 || item == 2390 || item == 2392 || item == 3120 || item == 3308 || item == 3512 || item == 4534 || item == 4986 || item == 5754 || item == 6144 || item == 6334 || item == 6694 || item == 6818 || item == 6842 || item == 1934 || item == 3134 || item == 6004 || item == 1780 || item == 2158 || item == 2160 || item == 2162 || item == 2164 || item == 2166 || item == 2168 || item == 2438 || item == 2538 || item == 2778 || item == 3858 || item == 350 || item == 998 || item == 1738 || item == 2642 || item == 2982 || item == 3104 || item == 3144 || item == 5738 || item == 3112 || item == 2722 || item == 3114 || item == 4970 || item == 4972 || item == 5020 || item == 6284 || item == 4184 || item == 4628 || item == 5322 || item == 4112 || item == 4114 || item == 3442) {
											((PlayerInfo*)(event.peer->data))->canDoubleJump = true;
										}
										else {
											((PlayerInfo*)(event.peer->data))->canDoubleJump = false;
										}
										// ^^^^ wings
										sendState(peer);
									}
									break;
								case 7:
									if (((PlayerInfo*)(event.peer->data))->cloth7 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth7 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth7 = pMov->plantingTree;
									break;
								case 8:
									if (((PlayerInfo*)(event.peer->data))->cloth8 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth8 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth8 = pMov->plantingTree;
									break;
								case 9:
									if (((PlayerInfo*)(event.peer->data))->cloth9 == pMov->plantingTree)
									{
										((PlayerInfo*)(event.peer->data))->cloth9 = 0;
										break;
									}
									((PlayerInfo*)(event.peer->data))->cloth9 = pMov->plantingTree;
									break;
								default:
#ifdef TOTAL_LOG
									cout << "Invalid item activated: " << pMov->plantingTree << " by " << ((PlayerInfo*)(event.peer->data))->displayName << endl;
#endif
									break;
								}
								sendClothes(peer);
								savejson(peer);
								ENetPeer* currentPeer;
								for (currentPeer = server->peers;
									currentPeer < &server->peers[server->peerCount];
									++currentPeer)
								{
									if (currentPeer->state != ENET_PEER_STATE_CONNECTED)
										continue;
									if (isHere(peer, currentPeer)) {
										Player::PlayAudio(currentPeer, "audio/change_clothes.wav", 135);
									}
								}
								// activate item
							END_CLOTHSETTER_FORCE:;
							}
							if (data2->packetType == 18)
							{
								sendPData(peer, pMov);
								// add talk buble
							}
							if (data2->punchX != -1 && data2->punchY != -1) {
								//cout << data2->packetType << endl;
								if (data2->packetType == 3)
								{
									WorldInfo* world = getPlyersWorld(peer);
									int x = ((PlayerInfo*)(peer->data))->x / 32;
									int y = ((PlayerInfo*)(peer->data))->y / 32;
									int x2 = ((PlayerInfo*)(peer->data))->x / 32;
									int y2 = ((PlayerInfo*)(peer->data))->y / 32;
									float xx = x2, yy = x2;
									if (x && y) {
										if (data2->punchX == x && data2->punchY == y) {

										}
									}
									if (data2->punchX < xx - 2 || data2->punchX > xx + 3 || data2->punchY < y - 2 || data2->punchY > y + 2) {
										if (data2->punchX < xx - 4 || data2->punchX > xx + 5 || data2->punchY < y - 4 || data2->punchY > y + 4) {

										}
										sendNothingHappened(peer, x, y);
										continue;
									}
									//sendTileUpdate(data2->punchX, data2->punchY, data2->plantingTree, ((PlayerInfo*)(event.peer->data))->netID, peer);
								}

								else {

								}
								/*PlayerMoving data;
								//data.packetType = 0x14;
								data.packetType = 0x3;
								//data.characterState = 0x924; // animation
								data.characterState = 0x0; // animation
								data.x = data2->punchX;
								data.y = data2->punchY;
								data.punchX = data2->punchX;
								data.punchY = data2->punchY;
								data.XSpeed = 0;
								data.YSpeed = 0;
								data.netID = ((PlayerInfo*)(event.peer->data))->netID;
								data.plantingTree = data2->plantingTree;
								SendPacketRaw(4, packPlayerMoving(&data), 56, 0, peer, ENET_PACKET_FLAG_RELIABLE);
								cout << "Tile update at: " << data2->punchX << "x" << data2->punchY << endl;*/

							}
							delete data2;
							delete pMov;
						}

						else {
							cout << "Got bad tank packet";
						}
						/*char buffer[2048];
						for (int i = 0; i < event->packet->dataLength; i++)
						{
						sprintf(&buffer[2 * i], "%02X", event->packet->data[i]);
						}
						cout << buffer;*/
					}
				}
				break;
				case 5:
					break;
				case 6:
					//cout << GetTextPointerFromPacket(event.packet) << endl;
					break;
				}
				enet_packet_destroy(event.packet);
				break;
			}
			case ENET_EVENT_TYPE_DISCONNECT:
#ifdef TOTAL_LOG
				printf("Peer disconnected.\n");
#endif
				/* Reset the peer's client information. */
				if (((PlayerInfo*)(peer->data))->currentWorld != "") {
					savejson(peer);
				}
				UpdateOnline();

				//sendPlayerLeave(peer, (PlayerInfo*)(event.peer->data));
				((PlayerInfo*)(event.peer->data))->inventory.items.clear();
				delete (PlayerInfo*)event.peer->data;
				event.peer->data = NULL;
			}
		}
	cout << "Program ended??? Huh?" << endl;
	while (1);
	return 0;
}
