
// tFormExampleDlg.h : файл заголовка
//

#pragma once
#include "../SChannel/iSoftwareKeyPingRP.h"

class ISoftwareKeyConnection;
class ICertificate;

// диалоговое окно TFormExampleDlg
class TFormExampleDlg : public CDialogEx,
                        public ISoftwareKeyPingRP
{
// Создание
public:
	TFormExampleDlg(CWnd* pParent = NULL);	// стандартный конструктор
  ~TFormExampleDlg();

// Данные диалогового окна
	enum { IDD = IDD_FORMEXAMPLE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// поддержка DDX/DDV


// Реализация
protected:
	HICON m_hIcon;

	// Созданные функции схемы сообщений
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

private:
  // ISoftwareKeyPingRP
  void onPingFail();

  void setStatus(const CString& astrMessage);

  bool m_fWasShown;

  // class data
  ISoftwareKeyConnection* m_pKey;
  ICertificate* m_pCert;
protected:
  afx_msg LRESULT OnUserSkfail(WPARAM wParam, LPARAM lParam);
public:
//  afx_msg void OnWindowPosChanged(WINDOWPOS* lpwndpos);
protected:
  afx_msg LRESULT OnUserFirstload(WPARAM wParam, LPARAM lParam);
public:
//  afx_msg void OnActivate(UINT nState, CWnd* pWndOther, BOOL bMinimized);
//  afx_msg void OnEnterIdle(UINT nWhy, CWnd* pWho);
//  afx_msg BOOL OnNcCreate(LPCREATESTRUCT lpCreateStruct);
  afx_msg void OnTimer(UINT_PTR nIDEvent);
  afx_msg void OnBnClickedButton3();
  afx_msg void OnBnClickedButton1();
  afx_msg void OnBnClickedButton2();
};
