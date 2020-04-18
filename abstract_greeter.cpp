/**
 * ogon - Free Remote Desktop Services
 * Qt Greeter - Abstract Greeter Class
 *
 * Copyright (c) 2013-2018 Thincast Technologies GmbH
 *
 * Authors:
 * David Fort <contact@hardening-consulting.com>
 * Martin Haimberger <martin.haimberger@thincast.com>
 *
 * This file may be used under the terms of the GNU Affero General
 * Public License version 3 as published by the Free Software Foundation
 * and appearing in the file LICENSE-AGPL included in the distribution
 * of this file.
 *
 * Under the GNU Affero General Public License version 3 section 7 the
 * copyright holders grant the additional permissions set forth in the
 * ogon Core AGPL Exceptions version 1 as published by
 * Thincast Technologies GmbH.
 *
 * For more information see the file LICENSE in the distribution of this file.
 */

#include <QtWidgets/QApplication>
#include <QLibraryInfo>
#include <QtGui/qpa/qplatformnativeinterface.h>

#include <qogon/qogon.h>

#include "abstract_greeter.h"
#include "lowres_greeter.h"
#include "nice_greeter.h"

/* ugly fix */
#undef minor
#undef major

#include "SBP.pb.h"


using namespace ogon::sbp;


AbstractGreeter::AbstractGreeter(quint32 sessionId, const QString &user, const QString &domain, bool useEffects, bool use16Bit) :
	mSessionId(sessionId),
	mOgon(0),
	mAuthReqTag(0),
	mLogoffReqTag(0)
{
	mQtTranslator.load("qt_en", QLibraryInfo::location(QLibraryInfo::TranslationsPath));
	mGreeterTranslator.load("greeter_en", TRANSLATIONS_DIR);
	mLocalizationFiles << "en" << "fr"  << "de";

	mLowResGreeter = new LowResGreeterWindow(this, user, domain);
	mUi = mNiceGreeter = new NiceGreeterWindow(this, user, domain);

	if(QGuiApplication::platformName() == "ogon") {
		QPlatformNativeInterface *native = QGuiApplication::platformNativeInterface();
		mOgon = qobject_cast<QOgonInterface *>(
				(QObject *)native->nativeResourceForIntegration(QOGON_RESSOURCE_STRING)
		);
		if(!mOgon)
			qFatal("unable to retrieve ogon interface");

		QObject *qobj = mOgon->asQObject();
		connect(qobj, SIGNAL(ogonConnectionEstablished()), this, SLOT(onConnectionEstablished()));
		connect(qobj, SIGNAL(ogonConnectionLost()), this, SLOT(onConnectionLost()));
		connect(qobj, SIGNAL(ogonScreenReady()), this, SLOT(onScreenReady()));
		connect(qobj, SIGNAL(ogonSbpReply(quint32,quint32,quint32,QByteArray)),
				this,
				SLOT(onSbpReply(quint32,quint32,quint32,QByteArray))
		);
	} else {
		qWarning("%s: not running under ogon", __FUNCTION__);
	}

	if (useEffects) {
		mLowResGreeter->setupEffects();
		mNiceGreeter->setupEffects();
	}

	if(!mOgon)
		onConnectionEstablished();

	mUse16Bit = use16Bit;
}

AbstractGreeter::~AbstractGreeter() {
	delete mLowResGreeter;
	delete mNiceGreeter;
}

QTranslator *AbstractGreeter::getTranslator() {
	return &mGreeterTranslator;
}

const QStringList &AbstractGreeter::getLocales() {
	return mLocalizationFiles;
}

QObject *AbstractGreeter::getQOgon() {
	if (!mOgon)
		return NULL;

	return mOgon->asQObject();
}


void AbstractGreeter::onConnectionEstablished() {

	if (mOgon) {
		VersionInfoRequest req;
		req.set_vmajor(SBP_VERSION_MAJOR);
		req.set_vminor(SBP_VERSION_MINOR);
		req.set_sessionid(mSessionId);

		QByteArray msg;
		int targetSize = req.ByteSize();
		msg.resize(targetSize);
		req.SerializeToArray(msg.data(), targetSize);

		mVersionInfoTag = mOgon->sbpCall(VersionInfo, msg);
	}

	mUi->onConnectionEstablished();
}

void AbstractGreeter::onConnectionLost() {
	mUi->onConnectionLost();
}

void AbstractGreeter::onScreenReady() {
	QString remoteLocale = mOgon->guessLocaleFromKeyboard();
	//qDebug("computed locale %s", remoteLocale.toLatin1().data());
	if(!remoteLocale.size())
		remoteLocale = "en";

	remoteLocale = remoteLocale.section('_', 0, 0);
	if(!mLocalizationFiles.contains(remoteLocale))
		remoteLocale = "en";

	//qWarning("setting locale to %s from " TRANSLATIONS_DIR, remoteLocale.toLatin1().data());
	if(!mGreeterTranslator.load("greeter_" + remoteLocale, TRANSLATIONS_DIR))
		qWarning("unable to load locale");

	QSize resolution = mOgon->getScreenSize();
	GreeterUi *targetUi = (resolution.width() < 640) ? mLowResGreeter : mNiceGreeter;
	if (mUi != targetUi) {
		mUi->hide();
		targetUi->show();
		mUi = targetUi;
	}

	mUi->setCurrentLanguage(remoteLocale);
}


void AbstractGreeter::onSbpReply(quint32 tag, quint32 sbpType, quint32 status,
									const QByteArray &reply)
{
	if(!mAuthReqTag && !mLogoffReqTag && !mVersionInfoTag) {
		qWarning("%s: receiving a response while no request was made", __FUNCTION__);
		return;
	}

	if(mAuthReqTag != tag && mLogoffReqTag != tag && mVersionInfoTag != tag) {
		qWarning("%s: received tag doesn't match current requests, tag=%x auth=%x endSesion=%x",
				__FUNCTION__, tag, mAuthReqTag, mLogoffReqTag);
		return;
	}

	switch(status) {
	case SBPCALL_SUCCESS:
		break;
	case SBPCALL_TRANSPORT:
	case SBPCALL_NOT_FOUND:
	case SBPCALL_UNKNOWN_ERROR:
		//TODO: handle all errors correctly
	default:
		mUi->setStatus("<b><font color='red'>" +
				tr("an error occured during the login process") +
				"</font></b>", true);
		qWarning("%s: error status=%d", __FUNCTION__, (int)status);
		mUi->onLoginFailed();
		switch(sbpType) {
			case AuthenticateUser:
				mAuthReqTag = 0;
				break;
			case EndSession:
				mLogoffReqTag = 0;
				break;
			case VersionInfo:
				mVersionInfoTag = 0;
				break;
		}
		return;
	}

	switch(sbpType) {
	case AuthenticateUser:
		handleAuthResponse(reply);
		break;
	case EndSession:
		handleEndResponse(reply);
		break;
	case VersionInfo:
		handleVersionInfoResponse(reply);
		break;
	default:
		qWarning("%s: unexpected SBP with type %d", __FUNCTION__, sbpType);
	}
}

void AbstractGreeter::handleAuthResponse(const QByteArray &reply) {
	QLineEdit *passwordWidget;
	AuthenticateUserResponse response;

	mAuthReqTag = 0;

	if(!response.ParseFromArray(reply.data(), reply.size())) {
		qWarning("%s: invalid authentication response", __FUNCTION__);
		mUi->setStatus("<b><font color='white'>" +
				tr("Ogon internal error") +
				"</font></b>",
				true
		);

		mUi->onLoginFailed();
		return;
	}

	switch(response.authstatus()) {
	case AuthenticateUserResponse::AUTH_SUCCESSFUL:
		mUi->setStatus("<b><font color='white'>" +
				tr("Login successful, waiting for logon") +
				"</font></b>",
				true
		);
		mUi->onLoginSuccessful();
		return;
	case AuthenticateUserResponse::AUTH_BAD_CREDENTIALS:
		mUi->setStatus("<b><font color='red'>" +
				tr("Login failed !") +
				"</font></b>",
				true
		);
		passwordWidget = mUi->getPasswordWidget();
		passwordWidget->setFocus();
		mUi->onLoginFailed();
		break;
	default:
		qWarning("%s: unexpected authStatus %d", __FUNCTION__, (int)response.authstatus());
		break;
	}
}

void AbstractGreeter::handleVersionInfoResponse(const QByteArray &reply) {
	VersionInfoResponse response;

	mVersionInfoTag = 0;

	if(!response.ParseFromArray(reply.data(), reply.size())) {
		qWarning("%s: invalid versioninfo response", __FUNCTION__);
		mUi->setStatus("<b><font color='white'>" +
				tr("Ogon internal error") +
				"</font></b>",
				true
		);
		return;
	}

	if (response.vmajor() != SBP_VERSION_MAJOR) {
		qWarning("%s: Received version %d.%d but used SBP version is %d.%d! Terminating greeter!",
			__FUNCTION__, response.vmajor(), response.vminor(),
			SBP_VERSION_MAJOR, SBP_VERSION_MINOR);
		mUi->close();
	}

}


void AbstractGreeter::handleEndResponse(const QByteArray & /*reply*/) {
	mLogoffReqTag = 0;
}


void AbstractGreeter::extractLoginAndDomain(const QString &input, QString *user, QString *domain) {
	int pos = input.indexOf('@');
	if(pos > 0) {
		// user@domain format
		*user = input.left(pos);
		*domain = input.mid(pos + 1);
		goto trim;
	}

	pos = input.indexOf('\\');
	if(pos > 0) {
		// domain\user format
		*domain = input.left(pos);
		*user = input.mid(pos + 1);
	} else {
		*user = input;
		*domain = QLatin1String("");
	}

trim:
	*user = user->trimmed();
	*domain = domain->trimmed();
}


void AbstractGreeter::loginPressed(const QString &login, const QString &password) {
	if(!mOgon)
		return;

	if(mAuthReqTag) {
		qWarning("%s: an authentication request is already in progress", __FUNCTION__);
		return;
	}

	// extract login / domain
	// the format user@domain and domain\user are supported
	QString loginString, domainString;
	extractLoginAndDomain(login, &loginString, &domainString);

	QByteArray loginBa = loginString.toUtf8();
	QByteArray domainBa = domainString.toUtf8();
	QByteArray passwordBa = password.toUtf8();

	AuthenticateUserRequest req;
	req.set_sessionid(mSessionId);
	req.set_username(loginBa.data(), loginBa.size());
	req.set_password(passwordBa.data(), passwordBa.size());
	req.set_domain(domainBa.data(), domainBa.size());

	QByteArray msg;
	int targetSize = req.ByteSize();
	msg.resize(targetSize);
	req.SerializeToArray(msg.data(), targetSize);

	mAuthReqTag = mOgon->sbpCall(AuthenticateUser, msg);
}

void AbstractGreeter::cancelPressed() {
	if(!mOgon) {
		// kill the application when we're in desktop mode
		QCoreApplication::quit();
		return;
	}

	if(mLogoffReqTag) {
		qWarning("%s: a logoff request is already in progress", __FUNCTION__);
		return;
	}

	EndSessionRequest req;
	req.set_sessionid(mSessionId);

	QByteArray msg;
	int targetSize = req.ByteSize();
	msg.resize(targetSize);
	req.SerializeToArray(msg.data(), targetSize);

	mLogoffReqTag = mOgon->sbpCall(EndSession, msg);
}


void AbstractGreeter::show() {
	mUi->show();
}

bool AbstractGreeter::is16Bit() {
	return mUse16Bit;
}
