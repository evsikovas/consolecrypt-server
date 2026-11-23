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
      language: "Язык",
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
      language: "Language",
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
    es: {
      title: "Cuenta de ConsoleCrypt",
      language: "Idioma",
      intro: "Confirma tu correo electrónico o cambia la contraseña de la cuenta con el código que recibiste por correo.",
      verifyTitle: "Confirmar correo electrónico",
      verifyHint: "Pega el código del mensaje de confirmación.",
      code: "Código del correo",
      verifyBtn: "Confirmar",
      verifying: "Confirmando el correo…",
      verifiedTitle: "Correo confirmado",
      verifiedText: "Ya puedes volver a la aplicación ConsoleCrypt e iniciar sesión.",
      forgotTitle: "¿Has olvidado la contraseña?",
      forgotHint: "Te enviaremos un código de un solo uso para cambiar la contraseña de tu cuenta.",
      email: "Correo de la cuenta",
      forgotBtn: "Enviar código",
      forgotSent: "Si la dirección está registrada, recibirás un correo con el código. Revisa también la carpeta de spam.",
      haveCode: "Ya tengo un código",
      resetTitle: "Nueva contraseña de la cuenta",
      resetHint: "Cambiar la contraseña de la cuenta no abre la bóveda. Para desbloquearla seguirás necesitando la frase de paso, la clave de recuperación o un dispositivo de confianza.",
      newPassword: "Nueva contraseña",
      repeatPassword: "Repite la contraseña",
      resetBtn: "Cambiar contraseña",
      resetDoneTitle: "Contraseña cambiada",
      resetDoneText: "Se han cerrado todas las sesiones. Inicia sesión en la aplicación ConsoleCrypt con la nueva contraseña.",
      denyTitle: "¿Reconoces este acceso?",
      denyText: "Este enlace procede de un aviso sobre un dispositivo nuevo o una actividad sospechosa. Si no reconoces el acceso, puedes revocar el dispositivo y cerrar sus sesiones. Los dispositivos que ya hayan desbloqueado la bóveda conservarán el acceso.",
      denyBtn: "No fui yo. Revocar dispositivo",
      cancel: "Cancelar",
      denyDoneTitle: "Solicitud de revocación procesada",
      denyRevoked: "Se han revocado estos dispositivos y cerrado sus sesiones:",
      denyAlready: "El dispositivo ya se había revocado.",
      denyNothing: "No hay dispositivos pendientes de confirmar que se puedan revocar.",
      denyNext: "Ahora puedes cambiar la contraseña de la cuenta. Te enviaremos un código por correo.",
      changePassword: "Cambiar la contraseña de la cuenta",
      back: "Volver",
      errCode: "Pega el código del correo. Empieza por «cct_».",
      errEmail: "Introduce tu correo electrónico.",
      errShort: "La contraseña es demasiado corta. Se necesitan al menos 12 bytes.",
      errLong: "La contraseña es demasiado larga.",
      errMismatch: "Las contraseñas no coinciden.",
      errInvalid: "El código no es válido, ha caducado o ya se ha utilizado. Solicita otro.",
      errDenyInvalid: "El enlace no es válido, ha caducado o ya se ha utilizado.",
      errDenyTrusted: "Este dispositivo ya ha desbloqueado la bóveda. Revócalo desde la aplicación en un dispositivo de confianza.",
      errRate: "Demasiados intentos. Vuelve a intentarlo en {s} s.",
      errServer: "El servidor no está disponible en este momento. Inténtalo más tarde.",
      errNetwork: "No se ha podido conectar con el servidor. Comprueba la conexión.",
    },
    zh: {
      title: "ConsoleCrypt 账户",
      language: "语言",
      intro: "使用邮件中的验证码确认邮箱地址或更改账户密码。",
      verifyTitle: "确认邮箱地址",
      verifyHint: "请粘贴邮箱确认邮件中的验证码。",
      code: "邮件验证码",
      verifyBtn: "确认",
      verifying: "正在确认邮箱…",
      verifiedTitle: "邮箱已确认",
      verifiedText: "现在可以返回 ConsoleCrypt 应用并登录。",
      forgotTitle: "忘记密码了？",
      forgotHint: "我们会向账户邮箱发送一次性验证码，用于更改账户密码。",
      email: "账户邮箱",
      forgotBtn: "发送验证码",
      forgotSent: "如果该邮箱已注册，你将收到包含验证码的邮件。请检查收件箱和垃圾邮件文件夹。",
      haveCode: "我已有验证码",
      resetTitle: "设置新的账户密码",
      resetHint: "更改账户密码后，仍需使用保险库口令、恢复密钥或受信任的设备来解锁保险库。",
      newPassword: "新密码",
      repeatPassword: "再次输入新密码",
      resetBtn: "更改密码",
      resetDoneTitle: "密码已更改",
      resetDoneText: "所有会话均已退出。请在 ConsoleCrypt 应用中使用新密码登录。",
      denyTitle: "这是你本人的操作吗？",
      denyText: "此链接来自新设备登录或异常活动的提醒邮件。如果不是你本人操作，可以撤销该设备并结束其会话。已解锁过保险库的设备不会受到影响。",
      denyBtn: "不是我，撤销此设备",
      cancel: "取消",
      denyDoneTitle: "设备撤销请求已处理",
      denyRevoked: "已撤销以下设备并结束其会话：",
      denyAlready: "此设备此前已被撤销。",
      denyNothing: "没有可撤销的待确认设备。",
      denyNext: "现在可以更改账户密码。我们会向你的账户邮箱发送验证码。",
      changePassword: "更改账户密码",
      back: "返回",
      errCode: "请粘贴邮件中以“cct_”开头的验证码。",
      errEmail: "请输入邮箱地址。",
      errShort: "密码太短，至少需要 12 个字节。",
      errLong: "密码太长。",
      errMismatch: "两次输入的密码不一致。",
      errInvalid: "验证码无效、已使用或已过期。请申请新的验证码。",
      errDenyInvalid: "链接无效、已使用或已过期。",
      errDenyTrusted: "此设备已解锁过保险库。请在受信任设备的应用中撤销它。",
      errRate: "尝试次数过多，请在 {s} 秒后重试。",
      errServer: "服务器暂时不可用，请稍后重试。",
      errNetwork: "无法连接到服务器，请检查网络连接。",
    },
  };
  const picker = document.getElementById("language");
  const storageKey = "consolecrypt.account.language";
  const supported = value => {
    const base = (value || "").toLowerCase().split("-")[0];
    return Object.hasOwn(STRINGS, base) ? base : null;
  };
  let stored;
  try { stored = localStorage.getItem(storageKey); } catch { /* Storage is optional. */ }
  let language = supported(new URLSearchParams(location.search).get("lang"))
    || supported(stored) || supported(document.documentElement.lang) || "en";

  function translate(node) {
    const value = STRINGS[language][node.dataset.message];
    node.textContent = node.dataset.seconds === undefined
      ? value : value.replace("{s}", node.dataset.seconds);
  }

  function msg(key, seconds) {
    const node = document.createElement("span");
    node.dataset.message = key;
    if (seconds !== undefined) node.dataset.seconds = String(seconds);
    translate(node);
    return node;
  }

  function applyLanguage() {
    document.documentElement.lang = language === "zh" ? "zh-Hans" : language;
    document.title = STRINGS[language].title;
    picker.value = language;
    document.querySelectorAll("[data-message]").forEach(translate);
  }

  picker.addEventListener("change", () => {
    language = picker.value;
    try { localStorage.setItem(storageKey, language); } catch { /* Private browsing. */ }
    const url = new URL(location.href);
    url.searchParams.set("lang", language);
    history.replaceState(null, "", url.pathname + url.search);
    applyLanguage();
  });
  applyLanguage();
  picker.parentElement.hidden = false;

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
    app.replaceChildren(...children);
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
      return { ok: false, message: msg("errNetwork") };
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
        return { ok: false, message: msg("errRate", data.retry_after_seconds || 60) };
      case "internal":
      case "unavailable":
        return { ok: false, message: msg("errServer") };
      default:
        return { ok: false, status: resp.status, data, message: msg("errInvalid") };
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
    const code = field(msg("code"), { class: "code", autocomplete: "one-time-code", spellcheck: "false", autocapitalize: "off" });
    const verifyBtn = el("button", { type: "submit" }, msg("verifyBtn"));
    const verifyForm = el(
      "form",
      {
        onsubmit: (e) => {
          e.preventDefault();
          const token = cleanCode(code.input.value);
          if (!validCode(token)) {
            return showError(verifyForm, msg("errCode"));
          }
          verify(token);
        },
      },
      el("h1", {}, msg("title")),
      el("p", {}, msg("intro")),
      message || null,
      el("hr"),
      el("h2", {}, msg("verifyTitle")),
      el("p", { class: "muted" }, msg("verifyHint")),
      code.node,
      verifyBtn,
    );

    const email = field(msg("email"), { type: "email", autocomplete: "email", inputmode: "email" });
    const forgotBtn = el("button", { type: "submit" }, msg("forgotBtn"));
    const forgotForm = el(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          const address = email.input.value.trim();
          if (!address.includes("@")) return showError(forgotForm, msg("errEmail"));
          busy(forgotBtn, true);
          const r = await post(PATHS.forgot, { email: address });
          busy(forgotBtn, false);
          if (!r.ok) return showError(forgotForm, r.message);
          resetForm(null, notice("ok", msg("forgotSent")));
        },
      },
      el("hr"),
      el("h2", {}, msg("forgotTitle")),
      el("p", { class: "muted" }, msg("forgotHint")),
      email.node,
      forgotBtn,
      el("button", { type: "button", class: "link", onclick: () => resetForm(null) }, msg("haveCode")),
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
    screen(el("h1", {}, msg("verifyTitle")), el("div", { class: "spinner", "aria-hidden": "true" }), el("p", {}, msg("verifying")));
    const r = await post(PATHS.verify, { token });
    if (r.ok) {
      screen(el("h1", {}, msg("verifiedTitle")), notice("ok", msg("verifiedText")));
    } else {
      home(notice("err", r.message));
    }
  }

  function resetForm(token, message, recovery) {
    const code = token ? null : field(msg("code"), { class: "code", autocomplete: "one-time-code", spellcheck: "false", autocapitalize: "off" });
    const pw1 = field(msg("newPassword"), { type: "password", autocomplete: "new-password" });
    const pw2 = field(msg("repeatPassword"), { type: "password", autocomplete: "new-password" });
    const submit = el("button", { type: "submit" }, msg("resetBtn"));
    const form = el(
      "form",
      {
        onsubmit: async (e) => {
          e.preventDefault();
          const t = token || cleanCode(code.input.value);
          if (!validCode(t)) return showError(form, msg("errCode"));
          const p = pw1.input.value;
          const bytes = byteLength(p);
          if (bytes < MIN_PASSWORD_BYTES) return showError(form, msg("errShort"));
          if (bytes > MAX_PASSWORD_BYTES) return showError(form, msg("errLong"));
          if (p !== pw2.input.value) return showError(form, msg("errMismatch"));
          busy(submit, true);
          const r = await post(recovery ? PATHS.recover : PATHS.reset, { token: t, new_password: p });
          busy(submit, false);
          if (!r.ok) return showError(form, r.message);
          screen(el("h1", {}, msg("resetDoneTitle")), notice("ok", msg("resetDoneText")));
        },
      },
      el("h1", {}, msg("resetTitle")),
      message || null,
      el("p", { class: "muted" }, msg("resetHint")),
      code ? code.node : null,
      pw1.node,
      pw2.node,
      submit,
      el("button", { type: "button", class: "link", onclick: () => home() }, msg("back")),
    );
    screen(form);
  }

  // "This wasn't me" (protocol 1.7): the token stays in this closure only and
  // is sent once, after an explicit click.
  function deny(token) {
    const confirm = el("button", { type: "button" }, msg("denyBtn"));
    const box = el(
      "div",
      {},
      el("h1", {}, msg("denyTitle")),
      el("p", {}, msg("denyText")),
      confirm,
      el("button", { type: "button", class: "link", onclick: () => home() }, msg("cancel")),
    );
    confirm.addEventListener("click", async () => {
      busy(confirm, true);
      const r = await post(PATHS.deny, { token });
      busy(confirm, false);
      if (!r.ok) {
        if (r.status === 400) return home(notice("err", msg("errDenyInvalid")));
        if (r.status === 403) return home(notice("err", msg("errDenyTrusted")));
        return showError(box, r.message);
      }
      const names = (r.data && r.data.revoked_device_names) || [];
      const result = names.length
        ? el("div", { class: "notice ok", role: "status" }, msg("denyRevoked"), el("ul", { class: "names" }, ...names.map((n) => el("li", {}, n))))
        : notice("ok", r.data && r.data.already_revoked ? msg("denyAlready") : msg("denyNothing"));
      screen(
        el("h1", {}, msg("denyDoneTitle")),
        result,
        el("p", {}, msg("denyNext")),
        el("button", { type: "button", class: "secondary", onclick: () => home(null, true) }, msg("changePassword")),
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
