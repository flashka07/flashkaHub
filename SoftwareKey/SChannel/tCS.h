#pragma once

class __declspec(dllexport) TCS
{
public:
  TCS();
  ~TCS();

  void lock();
  void unlock();

  bool isLocked();

private:
  void* m_pCS;
};

class __declspec(dllexport) TCSLockGuard
{
public:
  TCSLockGuard(TCS& aCS);
  ~TCSLockGuard();

private:
  TCSLockGuard() {}
  TCSLockGuard(const TCSLockGuard&) {}

  TCS* m_pCS;
};