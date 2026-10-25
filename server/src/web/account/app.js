// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
//
// Built-in account page (/account) of the ConsoleCrypt sync server.
//
// * Links from emails carry the single-use code in the URL fragment
//   (#action=verify|reset|recover|deny-device&token=…): fragments are never
//   sent to the server, and the page removes it from the address bar and
//   history right away.
// * It talks only to the public, code-based endpoints of this server
//   (same origin, enforced by CSP): verify email, request / complete a
//   password reset, "This wasn't me". No login, no cookies, no vault access.
// * "This wasn't me" needs an explicit click: mail scanners that open links
//   must not revoke devices.
// * The DOM is built with textContent only (no HTML injection).
"use strict";

(function () {
  const PATHS = {
    verify: "/v1/auth/email/verify",
    reset: "/v1/auth/password/reset",
    recover: "/v1/recovery/account/confirm",
    forgot: "/v1/auth/password/forgot",
    deny: "/v1/devices/deny",
  };
  const MIN_PASSWORD_BYTES = 12;
  const MAX_PASSWORD_BYTES = 1024;

  const STRINGS = {
    ru: {
      title: "Аккаунт ConsoleCrypt",
      intro: "Подтверждение email и смена пароля аккаунта по коду из письма.",
      verifyTitle: "Подтвердить email",
      verifyHint: "Вставьте код из письма «Подтвердите email».",
      code: "Код из письма",
      verifyBtn: "Подтвердить",
      verifying: "Подтверждаем email…",
      verifiedTitle: "Email подтверждён",
      verifiedText: "Готово. Вернитесь в приложение ConsoleCrypt и войдите.",
      forgotTitle: "Забыли пароль?",
      forgotHint: "Пришлём одноразовый код для смены пароля на адрес аккаунта.",
      email: "Email аккаунта",
      forgotBtn: "Отправить код",
      forgotSent: "Если такой адрес зарегистрирован, письмо с кодом уже отправлено. Проверьте почту (и папку «Спам»).",
      haveCode: "У меня уже есть код",
      resetTitle: "Новый пароль аккаунта",
      resetHint: "Пароль аккаунта не связан с хранилищем: после смены для хранилища по-прежнему нужны его парольная фраза, ключ восстановления или доверенное устройство.",
      newPassword: "Новый пароль (не короче 12 символов)",
      repeatPassword: "Повторите пароль",
      resetBtn: "Сменить пароль",
      resetDoneTitle: "Пароль изменён",
      resetDoneText: "Все сеансы завершены. Войдите в приложении ConsoleCrypt с новым паролем.",
      denyTitle: "Это были не вы?",
      denyText: "Ссылка из письма о входе с нового устройства или о подозрительной активности. Если это были не вы, сервер отзовёт это устройство и завершит его сеансы. Устройства, которые уже открывали хранилище, ссылка не затрагивает.",
      denyBtn: "Это не я — отозвать устройство",
      cancel: "Отмена",
      denyDoneTitle: "Устройство отозвано",
      denyRevoked: "Отозвано, сеансы завершены:",
      denyAlready: "Это устройство уже было отозвано.",
      denyNothing: "Неподтверждённых устройств для отзыва не найдено.",
      denyNext: "Теперь смените пароль аккаунта: мы пришлём код на адрес аккаунта.",
      changePassword: "Сменить пароль аккаунта",
      back: "На главную",
      errCode: "Вставьте код из письма — он начинается с «cct_».",
      errEmail: "Введите адрес электронной почты.",
      errShort: "Пароль слишком короткий: нужно не меньше 12 символов.",
      errLong: "Пароль слишком длинный.",
      errMismatch: "Пароли не совпадают.",
      errInvalid: "Код недействителен, уже использован или истёк. Запросите новый.",
      errDenyInvalid: "Ссылка недействительна, устарела или уже использована.",
      errDenyTrusted: "Это устройство уже открывало хранилище: отзовите его в приложении на доверенном устройстве.",
      errRate: "Слишком много попыток. Повторите через {s} с.",
      errServer: "Сервер временно недоступен. Попробуйте позже.",
      errNetwork: "Не удалось связаться с сервером. Проверьте подключение.",
    },
    en: {
      title: "ConsoleCrypt account",
      intro: "Confirm your email and change your account password with the code from our email.",
      verifyTitle: "Confirm email",
      verifyHint: "Paste the code from the “Confirm your email” message.",
      code: "Code from the email",
      verifyBtn: "Confirm",
      verifying: "Confirming your email…",
      verifiedTitle: "Email confirmed",
      verifiedText: "Done. Go back to the ConsoleCrypt app and sign in.",
      forgotTitle: "Forgot your password?",
      forgotHint: "We will email a one-time code to change the account password.",
      email: "Account email",
      forgotBtn: "Send code",
      forgotSent: "If this address is registered, an email with a code is on its way. Check your inbox (and spam).",
      haveCode: "I already have a code",
      resetTitle: "New account password",
      resetHint: "The account password is unrelated to your vault: afterwards the vault still needs its passphrase, your Recovery Key or a trusted device.",
      newPassword: "New password (at least 12 characters)",
      repeatPassword: "Repeat password",
      resetBtn: "Change password",
      resetDoneTitle: "Password changed",
      resetDoneText: "All sessions were signed out. Sign in to the ConsoleCrypt app with the new password.",
      denyTitle: "Wasn't this you?",
      denyText: "This link comes from an email about a new device or suspicious activity. If it wasn't you, the server revokes that device and ends its sessions. Devices that have already unlocked the vault are not affected.",
      denyBtn: "This wasn't me — revoke the device",
      cancel: "Cancel",
      denyDoneTitle: "Device revoked",
      denyRevoked: "Revoked, sessions ended:",
      denyAlready: "This device had already been revoked.",
      denyNothing: "No unconfirmed devices were found to revoke.",
      denyNext: "Now change your account password: we will email a code to the account address.",
      changePassword: "Change account password",
      back: "Back",
      errCode: "Paste the code from the email — it starts with “cct_”.",
      errEmail: "Enter your email address.",
      errShort: "The password is too short: at least 12 characters.",
      errLong: "The password is too long.",
      errMismatch: "The passwords do not match.",
      errInvalid: "The code is invalid, already used or expired. Request a new one.",
      errDenyInvalid: "The link is invalid, expired or already used.",
      errDenyTrusted: "This device has already unlocked the vault: revoke it in the app on a trusted device.",
      errRate: "Too many attempts. Try again in {s} s.",
      errServer: "The server is temporarily unavailable. Try again later.",
      errNetwork: "Could not reach the server. Check your connection.",
    },
  };
  const T = STRINGS[document.documentElement.lang === "en" ? "en" : "ru"];

  const app = document.getElementById("app");

  // ---- tiny DOM helpers (textContent only) ---------------------------------
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children) {
      if (c === null || c === undefined) continue;
      node.append(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return node;
  }

  function screen(...children) {
    app.replaceChildren(el("div", { class: "brand" }, "ConsoleCrypt"), ...children);
    const first = app.querySelector("input");
    if (first) first.focus();
  }

  function notice(kind, text) {
    return el("div", { class: "notice " + kind, role: kind === "err" ? "alert" : "status" }, text);
  }

  function field(label, attrs) {
    const input = el("input", attrs);
    return { input, node: el("label", {}, label, input) };
  }

  function busy(button, on) {
    button.disabled = on;
  }

  // ---- API ------------------------------------------------------------------
  async function post(path, body) {
    let resp;
    try {
      resp = await fetch(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch (_) {
      return { ok: false, message: T.errNetwork };
    }
    let data = {};
    try {
      data = await resp.json();
    } catch (_) {
      /* empty body (204) or not JSON */
    }
    if (resp.ok) return { ok: true, data };
    switch (data.code) {
      case "rate_limited":
        return { ok: false, message: T.errRate.replace("{s}", String(data.retry_after_seconds || 60)) };
      case "internal":
      case "unavailable":
        return { ok: false, message: T.errServer };
      default:
        return { ok: false, status: resp.status, data, message: T.errInvalid };
    }
  }

  function cleanCode(value) {
    return value.replace(/\s+/g, "");
  }

  function validCode(code) {
    return /^cct_[A-Za-z0-9_-]{20,}$/.test(code);
  }

  function validDenyToken(token) {
    return /^ccd_[A-Za-z0-9_-]{20,}$/.test(token);
  }

  function byteLength(s) {
    return new TextEncoder().encode(s).length;
  }

  // ---- screens --------------------------------------------------------------
  function home(message, focusForgot) {
    const code = field(T.code, { class: "code", autocomplete: "one-time-code", spellcheck: "false", autocapitalize: "off" });
    const verifyBtn = el("button", { type: "submit" }, T.verifyBtn);
    const verifyForm = el(
      "form",
      {
        onsubmit: (e) => {
          e.preventDefault();
          const token = cleanCode(code.input.value);
          if (!validCode(token)) {
            return showError(verifyForm, T.errCode);
          }
          verify(token);
        },
      },
      el("h1", {}, T.title),
      el("p", {}, T.intro),
      message || null,
      el("hr"),
      el("h2", {}, T.verifyTitle),
      el("p", { class: "muted" }, T.verifyHint),
      code.node,
      verifyBtn,
    );

    const email = field(T.email, { type: "email", autocomplete: "email", inputmode: "email" });
    const forgotBtn = el("button", { type: "submit" }, T.forgotBtn);
    const forgotForm = el(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          const address = email.input.value.trim();
          if (!address.includes("@")) return showError(forgotForm, T.errEmail);
          busy(forgotBtn, true);
          const r = await post(PATHS.forgot, { email: address });
          busy(forgotBtn, false);
          if (!r.ok) return showError(forgotForm, r.message);
          resetForm(null, notice("ok", T.forgotSent));
        },
      },
      el("hr"),
      el("h2", {}, T.forgotTitle),
      el("p", { class: "muted" }, T.forgotHint),
      email.node,
      forgotBtn,
      el("button", { type: "button", class: "link", onclick: () => resetForm(null) }, T.haveCode),
    );
    screen(verifyForm, forgotForm);
    if (focusForgot) email.input.focus();
  }

  function showError(container, text) {
    const old = container.querySelector(".notice.err");
    if (old) old.remove();
    container.append(notice("err", text));
  }

  async function verify(token) {
    screen(el("h1", {}, T.verifyTitle), el("div", { class: "spinner", "aria-hidden": "true" }), el("p", {}, T.verifying));
    const r = await post(PATHS.verify, { token });
    if (r.ok) {
      screen(el("h1", {}, T.verifiedTitle), notice("ok", T.verifiedText));
    } else {
      home(notice("err", r.message));
    }
  }

  function resetForm(token, message, recovery) {
    const code = token ? null : field(T.code, { class: "code", autocomplete: "one-time-code", spellcheck: "false", autocapitalize: "off" });
    const pw1 = field(T.newPassword, { type: "password", autocomplete: "new-password" });
    const pw2 = field(T.repeatPassword, { type: "password", autocomplete: "new-password" });
    const submit = el("button", { type: "submit" }, T.resetBtn);
    const form = el(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          const t = token || cleanCode(code.input.value);
          if (!validCode(t)) return showError(form, T.errCode);
          const p = pw1.input.value;
          const bytes = byteLength(p);
          if (bytes < MIN_PASSWORD_BYTES) return showError(form, T.errShort);
          if (bytes > MAX_PASSWORD_BYTES) return showError(form, T.errLong);
          if (p !== pw2.input.value) return showError(form, T.errMismatch);
          busy(submit, true);
          const r = await post(recovery ? PATHS.recover : PATHS.reset, { token: t, new_password: p });
          busy(submit, false);
          if (!r.ok) return showError(form, r.message);
          screen(el("h1", {}, T.resetDoneTitle), notice("ok", T.resetDoneText));
        },
      },
      el("h1", {}, T.resetTitle),
      message || null,
      el("p", { class: "muted" }, T.resetHint),
      code ? code.node : null,
      pw1.node,
      pw2.node,
      submit,
      el("button", { type: "button", class: "link", onclick: () => home() }, T.back),
    );
    screen(form);
  }

  // "This wasn't me" (protocol 1.7): the token stays in this closure only and
  // is sent once, after an explicit click.
  function deny(token) {
    const confirm = el("button", { type: "button" }, T.denyBtn);
    const box = el(
      "div",
      {},
      el("h1", {}, T.denyTitle),
      el("p", {}, T.denyText),
      confirm,
      el("button", { type: "button", class: "link", onclick: () => home() }, T.cancel),
    );
    confirm.addEventListener("click", async () => {
      busy(confirm, true);
      const r = await post(PATHS.deny, { token });
      busy(confirm, false);
      if (!r.ok) {
        if (r.status === 400) return home(notice("err", T.errDenyInvalid));
        if (r.status === 403) return home(notice("err", T.errDenyTrusted));
        return showError(box, r.message);
      }
      const names = (r.data && r.data.revoked_device_names) || [];
      const result = names.length
        ? el("div", { class: "notice ok", role: "status" }, T.denyRevoked, el("ul", { class: "names" }, ...names.map((n) => el("li", {}, n))))
        : notice("ok", r.data && r.data.already_revoked ? T.denyAlready : T.denyNothing);
      screen(
        el("h1", {}, T.denyDoneTitle),
        result,
        el("p", {}, T.denyNext),
        el("button", { type: "button", class: "secondary", onclick: () => home(null, true) }, T.changePassword),
      );
    });
    screen(box);
    confirm.focus();
  }

  // ---- entry: read and immediately drop the fragment --------------------------
  // Also on `hashchange`: following another email link while the page is open
  // only changes the fragment and does not reload the page.
  function route() {
    const params = new URLSearchParams(location.hash.slice(1));
    if (location.hash) {
      history.replaceState(null, "", location.pathname + location.search);
    }
    const action = params.get("action");
    const token = cleanCode(params.get("token") || "");
    if (action === "verify" && validCode(token)) {
      verify(token);
    } else if ((action === "reset" || action === "recover") && validCode(token)) {
      resetForm(token, null, action === "recover");
    } else if (action === "deny-device" && validDenyToken(token)) {
      deny(token);
    } else {
      home();
    }
  }
  window.addEventListener("hashchange", route);
  route();
})();
