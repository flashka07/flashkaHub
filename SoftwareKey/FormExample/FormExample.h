
// FormExample.h : ������� ���� ��������� ��� ���������� PROJECT_NAME
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�������� stdafx.h �� ��������� ����� ����� � PCH"
#endif

#include "resource.h"		// �������� �������


// TFormExampleApp:
// � ���������� ������� ������ ��. FormExample.cpp
//

class TFormExampleApp : public CWinApp
{
public:
	TFormExampleApp();

// ���������������
public:
	virtual BOOL InitInstance();

// ����������

	DECLARE_MESSAGE_MAP()
};

extern TFormExampleApp theApp;