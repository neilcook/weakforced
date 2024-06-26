/*
 * This file is part of PowerDNS or weakforced.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 3 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include "ext/luawrapper/include/LuaContext.hpp"
#include "misc.hh"
#include <mutex>
#include <thread>
#include "json11.hpp"
#include "login_tuple.hh"
#include "customfunc.hh"

typedef std::tuple<int, std::string, std::string, KeyValVector> AllowReturn;

typedef std::function<AllowReturn(const LoginTuple&)> allow_t;
extern allow_t g_allow;
typedef std::function<void(const LoginTuple&)> report_t;
extern report_t g_report;
typedef std::function<bool(const std::string&, const std::string&, const ComboAddress&)> reset_t;
extern reset_t g_reset;
typedef std::function<std::string(const std::string&)> canonicalize_t;

struct CustomFuncMapObject {
  custom_func_t c_func;
  bool c_reportSink;
};

typedef std::map<std::string, CustomFuncMapObject> CustomFuncMap;
extern CustomFuncMap g_custom_func_map;

typedef std::map<std::string, custom_get_func_t> CustomGetFuncMap;
extern CustomGetFuncMap g_custom_get_func_map;

vector<std::function<void(void)>>
setupLua(bool client, bool allow_report, LuaContext& c_lua, allow_t& allow_func, report_t& report_func,
         reset_t& reset_func, canonicalize_t& canon_func, CustomFuncMap& custom_func_map,
         CustomGetFuncMap& custom_get_func_map, const std::string& config);

struct LuaThreadContext {
  LuaContext lua_context;
  std::mutex lua_mutex;
  allow_t allow_func;
  report_t report_func;
  reset_t reset_func;
  canonicalize_t canon_func;
  CustomFuncMap custom_func_map;
  CustomGetFuncMap custom_get_func_map;
};

#define NUM_LUA_STATES 6

class LuaMultiThread {
public:

  LuaMultiThread() : num_states(NUM_LUA_STATES)
  {
    LuaMultiThread{num_states};
  }

  LuaMultiThread(unsigned int nstates) : num_states(nstates)
  {
    for (unsigned int i = 0; i < num_states; i++) {
      lua_pool.push_back(std::make_shared<LuaThreadContext>());
    }
    lua_read_only = lua_pool; // Make a copy for use by the control thread
  }

  LuaMultiThread(const LuaMultiThread&) = delete;

  LuaMultiThread& operator=(const LuaMultiThread&) = delete;

  // these are used to setup the allow and report function pointers
  std::vector<std::shared_ptr<LuaThreadContext>>::iterator begin()
  { return lua_read_only.begin(); }

  std::vector<std::shared_ptr<LuaThreadContext>>::iterator end()
  { return lua_read_only.end(); }

  bool reset(const std::string& type, const std::string& login_value, const ComboAddress& ca_value)
  {
    auto pool_member = getPoolMember();
    auto lt_context = pool_member.getLuaContext();
    // lock the lua state mutex
    std::lock_guard<std::mutex> lock(lt_context->lua_mutex);
    // call the reset function
    return lt_context->reset_func(type, login_value, ca_value);
  }

  AllowReturn allow(const LoginTuple& lt)
  {
    auto pool_member = getPoolMember();
    auto lt_context = pool_member.getLuaContext();
    // lock the lua state mutex
    std::lock_guard<std::mutex> lock(lt_context->lua_mutex);
    // call the allow function
    return lt_context->allow_func(lt);
  }

  void report(const LoginTuple& lt)
  {
    auto pool_member = getPoolMember();
    auto lt_context = pool_member.getLuaContext();
    // lock the lua state mutex
    std::lock_guard<std::mutex> lock(lt_context->lua_mutex);
    // call the report function
    lt_context->report_func(lt);
  }

  std::string canonicalize(const std::string& login)
  {
    auto pool_member = getPoolMember();
    auto lt_context = pool_member.getLuaContext();
    // lock the lua state mutex
    std::lock_guard<std::mutex> lock(lt_context->lua_mutex);
    // call the canonicalize function
    return lt_context->canon_func(login);
  }

  CustomFuncReturn custom_func(const std::string& command, const CustomFuncArgs& cfa, bool& reportSinkReturn)
  {
    auto pool_member = getPoolMember();
    auto lt_context = pool_member.getLuaContext();
    // lock the lua state mutex
    std::lock_guard<std::mutex> lock(lt_context->lua_mutex);
    // call the custom function
    for (const auto& i: lt_context->custom_func_map) {
      if (command.compare(i.first) == 0) {
        reportSinkReturn = i.second.c_reportSink;
        return i.second.c_func(cfa);
      }
    }
    return CustomFuncReturn(false, KeyValVector{});
  }

  std::string custom_get_func(const std::string& command)
  {
    auto pool_member = getPoolMember();
    auto lt_context = pool_member.getLuaContext();
    // lock the lua state mutex
    std::lock_guard<std::mutex> lock(lt_context->lua_mutex);
    // call the custom function
    for (const auto& i: lt_context->custom_get_func_map) {
      if (command.compare(i.first) == 0) {
        return i.second();
      }
    }
    return string();
  }

protected:

  class SharedPoolMember {
  public:
    SharedPoolMember(std::shared_ptr<LuaThreadContext> ptr, LuaMultiThread* pool) : d_pool_item(ptr), d_pool(pool) {}
    ~SharedPoolMember() { if (d_pool != nullptr) { d_pool->returnPoolMember(d_pool_item); } }
    SharedPoolMember(const SharedPoolMember&) = delete;
    SharedPoolMember& operator=(const SharedPoolMember&) = delete;
    std::shared_ptr<LuaThreadContext> getLuaContext() { return d_pool_item; }
  private:
    std::shared_ptr<LuaThreadContext> d_pool_item;
    LuaMultiThread* d_pool;
  };
  SharedPoolMember getPoolMember() {
    std::lock_guard<std::mutex> lock(mutx);
    auto member = lua_pool.back();
    lua_pool.pop_back();
    return SharedPoolMember(member, this);
  }
  void returnPoolMember(std::shared_ptr<LuaThreadContext> my_ptr) {
    std::lock_guard<std::mutex> lock(mutx);
    lua_pool.push_back(my_ptr);
  }

private:
  std::vector<std::shared_ptr<LuaThreadContext>> lua_pool;
  std::vector<std::shared_ptr<LuaThreadContext>> lua_read_only;
  unsigned int num_states;
  std::mutex mutx;
};

extern std::shared_ptr<LuaMultiThread> g_luamultip;
extern int g_num_luastates;
