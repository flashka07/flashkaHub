
// tFormExampleDlg.cpp : ���� ����������
//

#include "stdafx.h"
#include "FormExample.h"
#include "tFormExampleDlg.h"
#include "afxdialogex.h"


#include <Windows.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Schnlsp.h>
#include <memory>
#include <string>

#include "../SChannel/iSoftwareKeyConnection.h"
#include "../SChannel/iCertificate.h"
#include "../SChannel/tBlob.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_USER_SKFAIL WM_USER + 1234
#define WM_USER_FIRSTLOAD WM_USER + 1235
// ���������� ���� TFormExampleDlg


TFormExampleDlg::TFormExampleDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(TFormExampleDlg::IDD, pParent),
    m_fWasShown(false),
    m_pKey(ISoftwareKeyConnection::createInstance()),
    m_pCert(ICertificate::createInstance())
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

TFormExampleDlg::~TFormExampleDlg()
{
  if(m_pKey)
  {
    delete m_pKey;
    m_pKey = NULL;
  }
  if(m_pCert)
  {
    delete m_pCert;
    m_pCert = NULL;
  }
}

void TFormExampleDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(TFormExampleDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
  ON_MESSAGE(WM_USER_SKFAIL, &TFormExampleDlg::OnUserSkfail)
  ON_MESSAGE(WM_USER_FIRSTLOAD, &TFormExampleDlg::OnUserFirstload)
ON_WM_TIMER()
ON_BN_CLICKED(IDC_BUTTON3, &TFormExampleDlg::OnBnClickedButton3)
ON_BN_CLICKED(IDC_BUTTON1, &TFormExampleDlg::OnBnClickedButton1)
ON_BN_CLICKED(IDC_BUTTON2, &TFormExampleDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// ����������� ��������� TFormExampleDlg

BOOL TFormExampleDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ������ ������ ��� ����� ����������� ����. ����� ������ ��� �������������,
	//  ���� ������� ���� ���������� �� �������� ����������
	SetIcon(m_hIcon, TRUE);			// ������� ������
	SetIcon(m_hIcon, FALSE);		// ������ ������

	// TODO: �������� �������������� �������������
  SetTimer(55, 1000, NULL);
	return TRUE;  // ������� �������� TRUE, ���� ����� �� ������� �������� ����������
}

// ��� ���������� ������ ����������� � ���������� ���� ����� ��������������� ����������� ���� �����,
//  ����� ���������� ������. ��� ���������� MFC, ������������ ������ ���������� ��� �������������,
//  ��� ������������� ����������� ������� ��������.

void TFormExampleDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // �������� ���������� ��� ���������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ������������ ������ �� ������ ����������� ��������������
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ��������� ������
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// ������� �������� ��� ������� ��� ��������� ����������� ������� ��� �����������
//  ���������� ����.
HCURSOR TFormExampleDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void TFormExampleDlg::onPingFail()
{
  SendMessage(WM_USER_SKFAIL);
}

void TFormExampleDlg::setStatus(const CString& astrMessage)
{
  SetDlgItemText(IDC_ESTATUS, astrMessage);
  CEdit* pStatus = (CEdit*)GetDlgItem(IDC_ESTATUS);
  pStatus->UpdateWindow();
}

afx_msg LRESULT TFormExampleDlg::OnUserSkfail(WPARAM wParam, LPARAM lParam)
{
  setStatus(L"���������� � ������ ����������� ������ ��������!");
  MessageBox(
    L"���������� � ������ ����������� ������ ��������!\n���������� �������� ���� ������.", 
    L"������",
    MB_ICONWARNING);
  Sleep(200);
  SendMessage(WM_CLOSE);
  return 0;
}

afx_msg LRESULT TFormExampleDlg::OnUserFirstload(WPARAM wParam, LPARAM lParam)
{
  setStatus(L"����������� � ����� ����������� ������...");
  Sleep(300);
  int nResult = m_pKey->connect(
    *m_pCert,
    *this);
  if(nResult)
  {
    OnUserSkfail(0, 0);
    return -1;
  }

  setStatus(L"���������� � ������ ����������� ������ �����������");
  return 0;
}

void TFormExampleDlg::OnTimer(UINT_PTR nIDEvent)
{
  // TODO: �������� ���� ��� ����������� ��������� ��� ����� ������������
  if(nIDEvent == 55)
  {
    KillTimer(55);
    SendMessage(WM_USER_FIRSTLOAD);
  }
  __super::OnTimer(nIDEvent);
}


void TFormExampleDlg::OnBnClickedButton3()
{
  // TODO: �������� ���� ��� ����������� �����������
  CString strResult;
  GetDlgItemText(IDC_EDEST, strResult);
  SetDlgItemText(IDC_EDEST, L"");
  SetDlgItemText(IDC_ESORCE, strResult);
}


void TFormExampleDlg::OnBnClickedButton1()
{
  // TODO: �������� ���� ��� ����������� �����������
  if(!m_pKey)
    return;

  CString wstrSource;
  GetDlgItemText(IDC_ESORCE, wstrSource);

  CStringA strSource(wstrSource);
  size_t szLength = strSource.GetLength();
  TBlob vSource(szLength);
  char* pFirst = strSource.GetBuffer();
  vSource.assign(pFirst, pFirst + szLength);
  strSource.ReleaseBuffer();
  
  TBlob vEncrypted;
  int nResult = m_pKey->encryptData(
    vSource,
    vEncrypted);
  if(nResult)
  {
    MessageBox(
      L"���������� ����������� ���������", 
      L"������",
      MB_ICONERROR);
    return;
  }

  CString wstrResult;
  CString wstrTmp;
  for(TBlob::const_iterator i=vEncrypted.begin();
      i!=vEncrypted.end();
      ++i)
  {
    wstrTmp.Format(L"%02x", *i);
    wstrResult += wstrTmp;
  }

  SetDlgItemText(IDC_EDEST, wstrResult);
}


void TFormExampleDlg::OnBnClickedButton2()
{
  // TODO: �������� ���� ��� ����������� �����������
  if(!m_pKey)
    return;

  CString wstrSource;
  GetDlgItemText(IDC_ESORCE, wstrSource);
  size_t szLength = wstrSource.GetLength();
  TBlob vSource(szLength / 2);
  CString wstrTmp;
  for(size_t i=0; i<vSource.size(); ++i)
  {
    wstrTmp = wstrSource[i * 2];
    wstrTmp += wstrSource[i * 2 + 1];
    TCHAR* pEnd = NULL;
    vSource[i] = (BYTE)_tcstol(wstrTmp, &pEnd, 16);
  }

  TBlob vDecrypted;
  int nResult = m_pKey->decryptData(
    vSource,
    vDecrypted);
  if(nResult)
  {
    MessageBox(
      L"���������� ������������ ���������", 
      L"������",
      MB_ICONERROR);
    return;
  }

  CString wstrResult;
  for(TBlob::const_iterator i=vDecrypted.begin();
      i!=vDecrypted.end();
      ++i)
  {
    wstrResult += *i;
  }

  SetDlgItemText(IDC_EDEST, wstrResult);
}
