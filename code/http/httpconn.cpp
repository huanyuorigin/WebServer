#include "HttpConn.h"

const char *HttpConn::srcDir;
std::atomic<int> HttpConn::userCount;
bool HttpConn::isET;

HttpConn::HttpConn(/* args */)
{
    httpDeal.init(&readBuff_, &writeBuff_);
    iSocketFd_ = -1;
    struAddr_ = {0};
    isClose_ = true;
}

HttpConn::~HttpConn()
{
    Close();
}

void HttpConn::Close()
{
    if (isClose_ == false)
    {
        isClose_ = true;
        userCount--;
        close(iSocketFd_);
        DEBUG_I("Client[" << iSocketFd_ << "](" << GetIP() << ":" << GetPort() << ") quit, UserCount:" << (int)userCount);
    }
}

int HttpConn::GetFd() const
{
    return iSocketFd_;
};

struct sockaddr_in HttpConn::GetAddr() const
{
    return struAddr_;
}

const char *HttpConn::GetIP() const
{
    return inet_ntoa(struAddr_.sin_addr);
}

int HttpConn::GetPort() const
{
    return struAddr_.sin_port;
}

int HttpConn::init(int iFd, const sockaddr_in &struAddr)
{
    int iRet = -1;
    do
    {
        if (0 > iFd)
        {
            iRet = -1;
            break;
        }
        userCount++;
        struAddr_ = struAddr;
        iSocketFd_ = iFd;
        writeBuff_.RetrieveAll();
        readBuff_.RetrieveAll();
        isClose_ = false;
        DEBUG_I("Client[" << iSocketFd_ << "](" << GetIP() << ":" << GetPort() << ") in, userCount:" << (int)userCount);
        iRet = 0;
    } while (0);
    return iRet;
}

ssize_t HttpConn::read(int &saveErrno)
{
    ssize_t len = -1;
    char buff[512]; // 栈区
    do
    {
        memset(buff, 0, 512);
        do
        {
            len = readn(iSocketFd_, buff, 512);
            if (len <= 0)
            {
                saveErrno = errno;
                break;
            }
            DEBUG_D(len);
            std::string strHead(buff);
            size_t iIndex = strHead.find("\r\n\r\n");
            if (std::string::npos != iIndex)
            {
                iIndex += 4;
                DEBUG_D(iIndex);
            }
            else
            {
                break;
            }
            readBuff_.Append(buff, len);

            std::string strKey;
            if (0 == findStringKey(strHead, "Content-Length: ", "\r\n", strKey))
            {
                ssize_t iContentLen = atol(strKey.c_str());
                int iLeft = iContentLen + iIndex - 512;
                DEBUG_D(iLeft);

                if (iLeft > 0)
                {
                    char buf[512];
                    
                    while (iLeft > 0)
                    {
                        memset(buf,0,512);
                        int len = readn(iSocketFd_, buf, 512);
                        readBuff_.Append(buf,len);
                        DEBUG_D(iLeft);
                        iLeft -= len;
                    }

                }
            }
            else
            {
                break;
            }

            DEBUG_D(iIndex);

        } while (0);
        if (len <= 0)
        {
            break;
        }

    } while (isET);

    DEBUG_D(readBuff_.ReadableBytes());
    return len;
}
ssize_t HttpConn::write(int *saveErrno)
{
    ssize_t len = -1;
    do
    {
        /* code */

        len = send(iSocketFd_, writeBuff_.Peek(), writeBuff_.ReadableBytes(), 0); // 将iov的内容写到fd中
        if (len <= 0)
        {
            *saveErrno = errno;
            break;
        }
        else if (len == writeBuff_.ReadableBytes())
        {
            DEBUG_D("writelen" << len);
            writeBuff_.RetrieveAll();
            
            break;
        }
        else
        {
            writeBuff_.Retrieve(len);
        }
        if (0 == writeBuff_.ReadableBytes())
        {
            break;
        }
    } while (isET);
    return len;
}
// 写的总长度
int HttpConn::ToWriteBytes()
{
    return writeBuff_.ReadableBytes();
}

bool HttpConn::IsKeepAlive() const
{
    return httpDeal.IsKeepAlive();
}

bool HttpConn::process()
{
    if (readBuff_.ReadableBytes() <= 0)
    {
        return false;
    }
    httpDeal.processHttp();
    // std::string strHeaderRe = "HTTP/1.1 200 ok\r\n"
    //                           "Content-Length: 0\r\n\r\n";
    // writeBuff_.Append(strHeaderRe);
    DEBUG_D("prcess");
    return true;
}
