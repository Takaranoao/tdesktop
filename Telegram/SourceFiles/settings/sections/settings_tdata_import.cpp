/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "settings/sections/settings_tdata_import.h"

#include "base/flat_set.h"
#include "base/weak_ptr.h"
#include "core/application.h"
#include "core/file_utilities.h"
#include "lang/lang_keys.h"
#include "main/main_domain.h"
#include "storage/storage_tdata_import.h"
#include "ui/boxes/confirm_box.h"
#include "ui/layers/generic_box.h"
#include "ui/widgets/fields/password_input.h"
#include "ui/widgets/labels.h"
#include "ui/vertical_list.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"
#include "styles/style_layers.h"
#include "styles/style_settings.h"

namespace Settings {
namespace {

// NOTE: All user-facing strings are inline literals on purpose. Adding new
// tr:: keys requires editing the lang sources and relying on codegen, which is
// out of scope for this UI draft. These can be replaced with tr:: keys later.

[[nodiscard]] QString ErrorText(Storage::TdataImportError error) {
	switch (error) {
	case Storage::TdataImportError::NotATdataFolder:
		return u"This is not a valid tdata folder."_q;
	case Storage::TdataImportError::Corrupted:
		return u"Failed to read the tdata folder."_q;
	default:
		return u"Failed to read the tdata folder."_q;
	}
}

// Walks the parsed accounts, deduplicates by userId within this batch and
// imports each one. Returns { imported, skipped }.
[[nodiscard]] std::pair<int, int> DoImport(
		const std::vector<Storage::ImportedAccount> &accounts) {
	auto imported = 0;
	auto skipped = 0;
	auto seen = base::flat_set<uint64>();
	for (const auto &account : accounts) {
		if (!seen.emplace(account.userId).second) {
			++skipped;
			continue;
		}
		const auto added = Core::App().domain().importAccount(
			account.mtpAuthorization,
			account.userId);
		if (added) {
			++imported;
		} else {
			++skipped;
		}
	}
	return { imported, skipped };
}

// SessionController is destroyed and recreated when the active session
// switches (account switch / current account disconnect), while a box lives on
// the window and can outlive that recreation. So every deferred callback below
// holds a weak_ptr to the controller and re-acquires a strong pointer (with an
// early return on failure) before touching it.
void ShowResult(
		base::weak_ptr<Window::SessionController> weak,
		int imported,
		int skipped) {
	const auto strong = weak.get();
	if (!strong) {
		return;
	}
	const auto text = u"Imported %1 account(s), skipped %2."_q
		.arg(imported)
		.arg(skipped);
	strong->show(Ui::MakeInformBox(text));
}

void ShowImportConfirm(
		base::weak_ptr<Window::SessionController> weak,
		std::vector<Storage::ImportedAccount> accounts) {
	const auto strong = weak.get();
	if (!strong) {
		return;
	}
	const auto count = int(accounts.size());
	const auto text = u"Found %1 account(s) to import.\n\n"
		"Importing copies the session into this app. Do NOT keep using the "
		"source tdata to log in with the same account afterwards, or one "
		"side may get disconnected."_q.arg(count);
	const auto shared = std::make_shared<
		std::vector<Storage::ImportedAccount>>(std::move(accounts));
	strong->show(Ui::MakeConfirmBox({
		.text = text,
		.confirmed = [=](Fn<void()> &&close) {
			const auto strong = weak.get();
			if (!strong) {
				return;
			}
			const auto result = DoImport(*shared);
			close();
			ShowResult(weak, result.first, result.second);
		},
		.confirmText = u"Import"_q,
		.title = u"Import accounts from tdata"_q,
	}));
}

// Forward declaration: the passcode box can re-trigger itself on a wrong try.
void ShowPasscodeBox(
	base::weak_ptr<Window::SessionController> weak,
	QString dir,
	bool wrongPrevious);

// Reads the source folder with the given passcode and dispatches to the right
// box depending on the resulting error.
void HandleRead(
		base::weak_ptr<Window::SessionController> weak,
		const QString &dir,
		const QByteArray &passcode) {
	const auto strong = weak.get();
	if (!strong) {
		return;
	}
	auto result = Storage::ReadTdataAccounts(dir, passcode);
	switch (result.error) {
	case Storage::TdataImportError::None:
		ShowImportConfirm(weak, std::move(result.accounts));
		return;
	case Storage::TdataImportError::NeedPasscode:
		ShowPasscodeBox(weak, dir, false);
		return;
	case Storage::TdataImportError::WrongPasscode:
		ShowPasscodeBox(weak, dir, true);
		return;
	case Storage::TdataImportError::NotATdataFolder:
	case Storage::TdataImportError::Corrupted:
		strong->show(Ui::MakeInformBox(ErrorText(result.error)));
		return;
	}
}

void ShowPasscodeBox(
		base::weak_ptr<Window::SessionController> weak,
		QString dir,
		bool wrongPrevious) {
	const auto strong = weak.get();
	if (!strong) {
		return;
	}
	strong->show(Box([=](not_null<Ui::GenericBox*> box) {
		box->setTitle(rpl::single(u"Local passcode"_q));

		box->addRow(object_ptr<Ui::FlatLabel>(
			box,
			(wrongPrevious
				? u"Wrong passcode. Please try again."_q
				: u"This tdata is protected by a local passcode. "
					"Please enter it to continue."_q),
			st::boxLabel));

		// PasswordInput is a MaskedInputField and does not auto-resize inside
		// a row, so wrap it in a container that recenters it on resize (same
		// pattern as settings_local_passcode.cpp).
		const auto &st = st::settingLocalPasscodeInputField;
		auto container = object_ptr<Ui::RpWidget>(box);
		container->resize(container->width(), st.heightMin);
		const auto field = Ui::CreateChild<Ui::PasswordInput>(
			container.data(),
			st,
			rpl::single(u"Passcode"_q));
		container->geometryValue(
		) | rpl::on_next([=](const QRect &r) {
			field->moveToLeft((r.width() - field->width()) / 2, 0);
		}, container->lifetime());
		box->addRow(std::move(container));

		box->setFocusCallback([=] {
			field->setFocusFast();
		});

		const auto submit = [=] {
			const auto passcode = field->getLastText().toUtf8();
			box->closeBox();
			// HandleRead re-checks weak itself, but read the passcode and
			// close the box first regardless.
			HandleRead(weak, dir, passcode);
		};
		QObject::connect(
			field,
			&Ui::MaskedInputField::submitted,
			box.get(),
			submit);
		box->addButton(rpl::single(u"Continue"_q), submit);
		box->addButton(tr::lng_cancel(), [=] { box->closeBox(); });
	}));
}

} // namespace

void ShowImportTdataBox(not_null<Window::SessionController*> controller) {
	const auto parent = controller->window().widget().get();
	const auto weak = base::make_weak(controller);
	const auto handleFolder = [=](const QString &result) {
		if (result.isEmpty()) {
			return;
		}
		// HandleRead re-acquires a strong controller (or bails) internally.
		HandleRead(weak, result, QByteArray());
	};
	FileDialog::GetFolder(
		parent,
		u"Select source tdata folder"_q,
		QString(),
		handleFolder);
}

} // namespace Settings
