/*
 * Generic 1 header file log system
 * Must specify -DDEBUG to the compiler to show messages
 * usage: TRACE(arg1, arg2, ...)
 * Unpack variadic tricks : https://stackoverflow.com/questions/21806561/concatenating-strings-and-numbers-in-variadic-template-function
 * ONLY for debug/dev purpose, don't use to print normal log infos
 */

#ifndef DEV_LOG_HPP
#define DEV_LOG_HPP

#ifdef DEBUG
#define TRACE_START()       \
    {                       \
        Log::get().start(); \
    }
#define TRACE_STOP()       \
    {                      \
        Log::get().stop(); \
    }
#define TRACE_COLOR()              \
    {                              \
        Log::get().enable_color(); \
    }
#define TRACE_NOCOLOR()             \
    {                               \
        Log::get().disable_color(); \
    }
#define TRACE_NL_OFF()          \
    {                           \
        Log::get().enable_nl(); \
    }
#define TRACE_NL_ON()            \
    {                            \
        Log::get().disable_nl(); \
    }
#define TRACE_INFO(...)               \
    {                                 \
        Log::get().info(__VA_ARGS__); \
    }
#define TRACE_WARN(...)               \
    {                                 \
        Log::get().warn(__VA_ARGS__); \
    }
#define TRACE_ERROR(...)               \
    {                                  \
        Log::get().error(__VA_ARGS__); \
    }
#define TRACE(...)                     \
    {                                  \
        Log::get().plain(__VA_ARGS__); \
    }
#define TRACE_NL()       \
    {                    \
        Log::get().nl(); \
    }
#define TRACE_MEM(...)                                                     \
    {                                                                      \
        Log::get().error(__FILE__, ":", __LINE__, ":MEM: ", #__VA_ARGS__); \
    }
#else
#define TRACE_START()
#define TRACE_STOP()
#define TRACE_COLOR()
#define TRACE_NOCOLOR()
#define TRACE_NL_OFF()
#define TRACE_NL_ON()
#define TRACE_INFO(...)
#define TRACE_WARN(...)
#define TRACE_ERROR(...)
#define TRACE(...)
#define TRACE_NL()
#define TRACE_MEM(...)
#endif

#ifdef DEBUG

#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>

#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004

static void _activateVirtualTerminal()
{
    HANDLE handleOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode;
    GetConsoleMode(handleOut, &consoleMode);
    consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(handleOut, consoleMode);
}
#endif

/**
 * This is a singleton
 */
class Log
{
public:
    static constexpr const char* logfile = "logs.txt";
    static constexpr const char* no_header = "";
    static constexpr const char* error_header = "[ERROR]";
    static constexpr const char* warning_header = "[WARN]";
    static constexpr const char* info_header = "[INFO]";
    static constexpr const char* error_color = "\033[31m";
    static constexpr const char* warning_color = "\033[35m";
    static constexpr const char* info_color = "\033[32m";
    static constexpr const char* reset_color = "\033[0m";

    static Log& get()
    {
        static Log m_singleton;
        return m_singleton;
    }

    void start() { m_enable = true; }
    void stop() { m_enable = false; }
    void enable_color() { m_color = true; }
    void disable_color() { m_color = false; }
    void enable_nl() { m_nl = true; }
    void disable_nl() { m_nl = false; }

    void nl() const noexcept { print(nullptr, nullptr); }
    template <typename... Args>
    void error(Args &&...p_args) const noexcept
    {
        print(error_header, error_color, std::forward<Args>(p_args)...);
    }
    template <typename... Args>
    void warn(Args &&...p_args) const noexcept
    {
        print(warning_header, warning_color, std::forward<Args>(p_args)...);
    }
    template <typename... Args>
    void info(Args &&...p_args) const noexcept
    {
        print(info_header, info_color, std::forward<Args>(p_args)...);
    }
    template <typename... Args>
    void plain(Args &&...p_args) const noexcept
    {
        print(nullptr, nullptr, std::forward<Args>(p_args)...);
    }

private:
    bool m_enable;
    bool m_color;
    bool m_nl;

    Log() : m_enable(true), m_color(true), m_nl(true) {
#ifdef _WIN32
        _activateVirtualTerminal();
#endif
    } ///< Constructor
    ~Log() = default;                                   ///< Default destructor
    Log(Log const&) = delete;                           ///< Copy constructor
    Log(Log&&) = delete;                                ///< Move constructor
    Log& operator=(Log const&) = delete;                ///< Copy assignment
    Log& operator=(Log&&) = delete;                     ///< Move assignment

    template <typename... Args>
    void print(const char* p_header, const char* p_color, Args &&...args) const
    {
#if defined(_WIN32)
        static const HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
#endif
        if (!m_enable)
            return;
        std::ostringstream msg_tt;
        if (p_header != nullptr)
        {
            if (m_color)
            {
                msg_tt << p_color;
            }
            msg_tt << p_header;
            if (m_color)
            {
                msg_tt << reset_color;
            }
            msg_tt << "\t";
        }
        int unpack[]{ 0, (msg_tt << args, 0)... }; // Side effect
        (void)unpack;                            // Avoid -Wunused warnings
        if (m_nl)
            std::cout << msg_tt.str() << std::endl;
        else
            std::cout << msg_tt.str() << std::flush;
    }
};

#endif // DLOG

#endif
