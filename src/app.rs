use leptos::prelude::*;
use leptos::task::spawn_local;
use rustchk_core::{
    matches, parse_expected, Algo, AppError, Expected, FileReport, KeyInfo, Lang, ParseError, Progress,
    SignatureStatus, Sidecar,
};
use serde::{Deserialize, Serialize};

use crate::i18n::{date_locale, T};
use crate::tauri::{self, LangArgs, NoArgs};

#[derive(Serialize)]
struct PathArgs {
    path: String,
}

#[derive(Serialize)]
struct FingerprintArgs {
    fingerprint: String,
}

#[derive(Serialize)]
struct ShellArgs {
    enabled: bool,
    lang: Lang,
}

#[derive(Serialize)]
struct TitleArgs {
    title: String,
}

#[derive(Deserialize)]
struct DropPayload {
    paths: Vec<String>,
}

/// Résultat de la comparaison entre l'empreinte attendue et celles du fichier.
#[derive(Clone, Debug, PartialEq)]
enum Verdict {
    /// Pas encore de fichier ou calcul en cours.
    Pending,
    /// Calcul terminé, aucune empreinte à comparer.
    NothingToCompare,
    Invalid,
    Match(Algo),
    Mismatch(Algo),
}

fn verdict_for(report: Option<&FileReport>, expected: &Result<Expected, ParseError>) -> Verdict {
    let Some(report) = report else {
        return Verdict::Pending;
    };
    match expected {
        Err(ParseError::Empty) => Verdict::NothingToCompare,
        Err(ParseError::Invalid) => Verdict::Invalid,
        Ok(e) if matches(e, &report.hashes) => Verdict::Match(e.algo),
        Ok(e) => Verdict::Mismatch(e.algo),
    }
}

/// Dernier message d'une opération de trousseau : stocké sous forme de données (et non de texte)
/// pour suivre un changement de langue.
#[derive(Clone)]
enum KeyMsg {
    Imported(Vec<KeyInfo>),
    Failed(AppError),
}

#[derive(Clone)]
enum ShellMsg {
    Added,
    Removed,
    Failed(AppError),
}

/// `ABCD1234…` → `ABCD 1234 …` pour comparer à l'œil avec l'empreinte publiée.
fn group_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_date(lang: Lang, unix_secs: u64) -> String {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(unix_secs as f64 * 1000.0));
    date.to_locale_date_string(date_locale(lang), &wasm_bindgen::JsValue::UNDEFINED)
        .as_string()
        .unwrap_or_default()
}

#[component]
pub fn App() -> impl IntoView {
    let lang = RwSignal::new(tauri::initial_lang());
    let t = move || T(lang.get());

    let file = RwSignal::new(None::<String>);
    let report = RwSignal::new(None::<FileReport>);
    let progress = RwSignal::new(None::<Progress>);
    let error = RwSignal::new(None::<AppError>);
    let expected_text = RwSignal::new(String::new());
    let sidecar = RwSignal::new(None::<Sidecar>);
    let dragging = RwSignal::new(false);
    let shell_on = RwSignal::new(false);
    let shell_msg = RwSignal::new(None::<ShellMsg>);
    let signature = RwSignal::new(None::<SignatureStatus>);
    let keys = RwSignal::new(Vec::<KeyInfo>::new());
    let key_msg = RwSignal::new(None::<KeyMsg>);

    let expected = Memo::new(move |_| expected_text.with(|t| parse_expected(t)));
    let verdict = Memo::new(move |_| report.with(|r| verdict_for(r.as_ref(), &expected.get())));
    // La carte d'authenticité ne vaut que tant que l'empreinte comparée est celle du fichier signé.
    let sidecar_in_use = Memo::new(move |_| {
        sidecar
            .get()
            .filter(|s| expected.get().is_ok_and(|e| e.hash == s.hash))
    });

    // Langue du document, titre de la page et de la fenêtre, préférence mémorisée.
    Effect::new(move |_| {
        let l = lang.get();
        let title = T(l).window_title();
        tauri::apply_lang(l, title);
        spawn_local(async move {
            let _: Result<(), AppError> =
                tauri::invoke("set_window_title", &TitleArgs { title: title.to_string() }).await;
        });
    });

    let set_lang = move |new: Lang| {
        if lang.get_untracked() == new {
            return;
        }
        lang.set(new);
        // Le libellé de l'entrée du menu contextuel est écrit dans le registre : le mettre à jour aussi.
        if shell_on.get_untracked() {
            spawn_local(async move {
                let _: Result<bool, AppError> =
                    tauri::invoke("shell_set", &ShellArgs { enabled: true, lang: new }).await;
            });
        }
    };

    let refresh_keys = move || {
        spawn_local(async move {
            if let Ok(list) = tauri::invoke::<_, Vec<KeyInfo>>("list_keys", &NoArgs {}).await {
                keys.set(list);
            }
        });
    };

    // Authentifie le fichier de checksums avec le trousseau ; ignore la réponse si l'utilisateur
    // est passé à un autre fichier entre-temps.
    let check_signature = move |checksum_path: String| {
        signature.set(None);
        spawn_local(async move {
            let status: Result<SignatureStatus, AppError> =
                tauri::invoke("verify_signature", &PathArgs { path: checksum_path.clone() }).await;
            let current = sidecar.get_untracked().map(|s| s.path);
            if current.as_deref() == Some(checksum_path.as_str()) {
                signature.set(Some(status.unwrap_or_else(|e| SignatureStatus::Invalid {
                    reason: rustchk_core::InvalidReason::ReadFailed { detail: format!("{e:?}") },
                })));
            }
        });
    };

    let import_key = move || {
        spawn_local(async move {
            let picked: Result<Option<String>, AppError> =
                tauri::invoke("pick_key_file", &LangArgs { lang: lang.get_untracked() }).await;
            let Ok(Some(path)) = picked else {
                return;
            };
            match tauri::invoke::<_, Vec<KeyInfo>>("import_key", &PathArgs { path }).await {
                Ok(imported) => {
                    key_msg.set(Some(KeyMsg::Imported(imported)));
                    refresh_keys();
                    if let Some(sc) = sidecar.get_untracked() {
                        check_signature(sc.path);
                    }
                }
                Err(e) => key_msg.set(Some(KeyMsg::Failed(e))),
            }
        });
    };

    let remove_key = move |fingerprint: String| {
        spawn_local(async move {
            let _: Result<(), AppError> = tauri::invoke("remove_key", &FingerprintArgs { fingerprint }).await;
            refresh_keys();
            if let Some(sc) = sidecar.get_untracked() {
                check_signature(sc.path);
            }
        });
    };

    let load = move |path: String| {
        file.set(Some(path.clone()));
        report.set(None);
        error.set(None);
        sidecar.set(None);
        signature.set(None);
        expected_text.set(String::new());
        progress.set(Some(Progress { done: 0, total: 0 }));

        let still_current = move |p: &str| file.get_untracked().as_deref() == Some(p);

        let sidecar_path = path.clone();
        spawn_local(async move {
            let found: Result<Option<Sidecar>, _> =
                tauri::invoke("find_sidecar", &PathArgs { path: sidecar_path.clone() }).await;
            if let Ok(Some(found)) = found {
                if still_current(&sidecar_path) && expected_text.get_untracked().trim().is_empty() {
                    expected_text.set(found.hash.clone());
                    let checksum_path = found.path.clone();
                    sidecar.set(Some(found));
                    check_signature(checksum_path);
                }
            }
        });

        spawn_local(async move {
            let result: Result<FileReport, AppError> =
                tauri::invoke("compute_hashes", &PathArgs { path: path.clone() }).await;
            if !still_current(&path) {
                return;
            }
            progress.set(None);
            match result {
                Ok(r) => report.set(Some(r)),
                Err(AppError::Cancelled) => {}
                Err(e) => error.set(Some(e)),
            }
        });
    };

    let pick = move |_| {
        spawn_local(async move {
            let picked: Result<Option<String>, AppError> =
                tauri::invoke("pick_file", &LangArgs { lang: lang.get_untracked() }).await;
            if let Ok(Some(path)) = picked {
                load(path);
            }
        });
    };

    let cancel = move |_| {
        spawn_local(async move {
            let _: Result<(), AppError> = tauri::invoke("cancel_hash", &NoArgs {}).await;
        });
        file.set(None);
        progress.set(None);
    };

    let toggle_shell = move |ev| {
        let enabled = event_target_checked(&ev);
        spawn_local(async move {
            let args = ShellArgs { enabled, lang: lang.get_untracked() };
            match tauri::invoke::<_, bool>("shell_set", &args).await {
                Ok(now) => {
                    shell_on.set(now);
                    shell_msg.set(Some(if now { ShellMsg::Added } else { ShellMsg::Removed }));
                }
                Err(e) => {
                    shell_on.set(!enabled);
                    shell_msg.set(Some(ShellMsg::Failed(e)));
                }
            }
        });
    };

    // Abonnements et état initial, une seule fois au montage.
    spawn_local(async move {
        tauri::listen::<Progress>("hash-progress", move |p| progress.set(Some(p))).await;
        tauri::listen::<serde::de::IgnoredAny>("tauri://drag-enter", move |_| dragging.set(true)).await;
        tauri::listen::<serde::de::IgnoredAny>("tauri://drag-leave", move |_| dragging.set(false)).await;
        tauri::listen::<DropPayload>("tauri://drag-drop", move |d| {
            dragging.set(false);
            if let Some(path) = d.paths.into_iter().next() {
                load(path);
            }
        })
        .await;

        refresh_keys();
        if let Ok(on) = tauri::invoke::<_, bool>("shell_status", &NoArgs {}).await {
            shell_on.set(on);
        }
        let initial: Result<Option<String>, AppError> = tauri::invoke("initial_file", &NoArgs {}).await;
        if let Ok(Some(path)) = initial {
            load(path);
        }
    });

    let percent = move || {
        progress
            .get()
            .map(|p| if p.total == 0 { 0.0 } else { p.done as f64 / p.total as f64 * 100.0 })
            .unwrap_or(0.0)
    };

    view! {
        <main class="app" class:dragging=move || dragging.get()>
            <header class="top">
                <img class="logo" src="128x128.png" alt="" width="40" height="40" />
                <div class="title">
                    <h1>"RustChk"</h1>
                    <p class="sub">{move || t().subtitle()}</p>
                </div>
                <div class="lang" role="group" attr:aria-label=move || t().language()>
                    {Lang::ALL
                        .into_iter()
                        .map(|l| view! {
                            <button
                                class:active=move || lang.get() == l
                                attr:aria-pressed=move || (lang.get() == l).to_string()
                                on:click=move |_| set_lang(l)
                            >
                                {l.tag().to_uppercase()}
                            </button>
                        })
                        .collect_view()}
                </div>
            </header>

            <section class="card">
                {move || match file.get() {
                    None => view! {
                        <div class="drop">
                            <p class="drop-title">{move || t().drop_title()}</p>
                            <p class="muted">{move || t().or()}</p>
                            <button class="primary" on:click=pick>{move || t().choose_file()}</button>
                        </div>
                    }
                    .into_any(),
                    Some(path) => {
                        let name = report
                            .get()
                            .map(|r| r.name)
                            .unwrap_or_else(|| path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string());
                        view! {
                            <div class="file">
                                <div class="file-info">
                                    <p class="file-name">{name}</p>
                                    <p class="file-path" title=path.clone()>{path.clone()}</p>
                                    {move || report.get().map(|r| view! {
                                        <p class="muted">{t().size_and_time(r.size, r.elapsed_ms)}</p>
                                    })}
                                </div>
                                <button on:click=pick>{move || t().change()}</button>
                            </div>
                        }
                        .into_any()
                    }
                }}

                {move || progress.get().map(|_| view! {
                    <div class="progress-wrap">
                        <div class="progress"><div class="bar" style=move || format!("width:{:.1}%", percent())></div></div>
                        <div class="progress-line">
                            <span class="muted">{move || t().hashing_progress(percent())}</span>
                            <button class="link" on:click=cancel>{move || t().cancel()}</button>
                        </div>
                    </div>
                })}

                {move || error.get().map(|e| view! { <p class="banner ko">{t().error(&e)}</p> })}
            </section>

            <Show when=move || file.get().is_some()>
                <section class="card">
                    <label class="field-label" for="expected">{move || t().expected_label()}</label>
                    <textarea
                        id="expected"
                        rows="2"
                        spellcheck="false"
                        placeholder=move || t().expected_placeholder()
                        prop:value=move || expected_text.get()
                        on:input=move |ev| expected_text.set(event_target_value(&ev))
                    ></textarea>
                    {move || sidecar.get().map(|s| view! {
                        <p class="muted small">
                            {t().sidecar_read_before()}<code>{s.source}</code>{t().sidecar_read_after()}
                        </p>
                    })}

                    {move || match verdict.get() {
                        Verdict::Pending => view! { <p class="banner wait">{t().verdict_pending()}</p> }.into_any(),
                        Verdict::NothingToCompare => view! {
                            <p class="banner wait">{t().verdict_nothing()}</p>
                        }.into_any(),
                        Verdict::Invalid => view! { <p class="banner warn">{t().verdict_invalid()}</p> }.into_any(),
                        Verdict::Match(a) => {
                            // Une empreinte qui colle mais dont le fichier de checksums est rejeté par sa
                            // signature ne prouve rien : ne pas afficher de succès.
                            let forged = sidecar_in_use.get().is_some()
                                && matches!(signature.get(), Some(SignatureStatus::Invalid { .. }));
                            if forged {
                                view! { <p class="banner ko">{t().verdict_forged(a)}</p> }.into_any()
                            } else {
                                view! { <p class="banner ok">{t().verdict_match(a)}</p> }.into_any()
                            }
                        }
                        Verdict::Mismatch(a) => view! { <p class="banner ko">{t().verdict_mismatch(a)}</p> }.into_any(),
                    }}
                </section>

                {move || sidecar_in_use.get().map(|sc| {
                    let source = sc.source.clone();
                    let body = move || match signature.get() {
                        None => view! { <p class="banner wait">{t().sig_checking()}</p> }.into_any(),
                        Some(SignatureStatus::Absent) => {
                            view! { <p class="banner warn">{t().sig_absent(&source)}</p> }.into_any()
                        }
                        Some(SignatureStatus::Valid { key, signed_at, key_expired }) => {
                            let l = lang.get();
                            let date = signed_at.map(|s| format_date(l, s));
                            let signer = t().key_name(&key);
                            let (class, headline) = if key_expired {
                                ("banner warn", t().sig_valid_expired(&signer, &key.key_id, date.as_deref()))
                            } else {
                                ("banner ok", t().sig_valid(&source, &signer, &key.key_id, date.as_deref()))
                            };
                            view! {
                                <p class=class>{headline}</p>
                                <p class="muted small">
                                    {t().key_fingerprint()}<code>{group_fingerprint(&key.fingerprint)}</code>
                                </p>
                                <p class="muted small">{t().key_compare_hint()}</p>
                            }.into_any()
                        }
                        Some(SignatureStatus::UnknownKey { issuer }) => view! {
                            <p class="banner warn">
                                {t().sig_unknown_before()}<code>{group_fingerprint(&issuer)}</code>{t().sig_unknown_after()}
                            </p>
                            <p class="actions">
                                <button on:click=move |_| import_key()>{t().import_vendor_key()}</button>
                            </p>
                        }.into_any(),
                        Some(SignatureStatus::Invalid { reason }) => {
                            view! { <p class="banner ko">{t().sig_rejected(&reason)}</p> }.into_any()
                        }
                    };
                    view! {
                        <section class="card">
                            <h2>{move || t().sig_title(&sc.source)}</h2>
                            {body}
                        </section>
                    }
                })}

                {move || report.get().map(|r| {
                    let compared = expected.get().ok().map(|e| e.algo);
                    let rows = Algo::ALL
                        .into_iter()
                        .map(|algo| {
                            let hash = r.hashes.get(algo).to_string();
                            let class = match (compared, verdict.get()) {
                                (Some(a), Verdict::Match(_)) if a == algo => "hash-row hit",
                                (Some(a), Verdict::Mismatch(_)) if a == algo => "hash-row miss",
                                _ => "hash-row",
                            };
                            let copy = hash.clone();
                            view! {
                                <div class=class>
                                    <span class="algo">{algo.label()}</span>
                                    <code class="hash">{hash}</code>
                                    <button
                                        class="copy"
                                        title=move || t().copy()
                                        on:click=move |_| tauri::copy_to_clipboard(&copy)
                                    >
                                        {move || t().copy()}
                                    </button>
                                </div>
                            }
                        })
                        .collect_view();
                    view! { <section class="card"><h2>{move || t().computed_title()}</h2>{rows}</section> }
                })}
            </Show>

            <details class="card keyring">
                <summary>{move || t().keyring_title(keys.get().len())}</summary>
                <p class="muted small">{move || t().keyring_help()}</p>
                <For
                    each=move || keys.get()
                    key=|k| k.fingerprint.clone()
                    children=move |k| {
                        let fingerprint = k.fingerprint.clone();
                        let (name_key, expires, revoked) = (k.clone(), k.expires, k.revoked);
                        view! {
                            <div class="key-row">
                                <div>
                                    <p class="key-name">{move || t().key_name(&name_key)}</p>
                                    <code class="small">{group_fingerprint(&k.fingerprint)}</code>
                                    {move || if revoked {
                                        Some(view! { <span class="tag">{t().key_revoked().to_string()}</span> })
                                    } else {
                                        expires.map(|e| view! {
                                            <span class="tag">{t().key_expires(&format_date(lang.get(), e))}</span>
                                        })
                                    }}
                                </div>
                                <button on:click=move |_| remove_key(fingerprint.clone())>{move || t().remove()}</button>
                            </div>
                        }
                    }
                />
                <p class="actions"><button on:click=move |_| import_key()>{move || t().import_key()}</button></p>
                {move || key_msg.get().map(|m| match m {
                    KeyMsg::Imported(list) => view! { <p class="muted small">{t().keys_imported(&list)}</p> }.into_any(),
                    KeyMsg::Failed(e) => view! { <p class="banner ko">{t().error(&e)}</p> }.into_any(),
                })}
            </details>

            <footer class="card shell">
                <label class="switch">
                    <input type="checkbox" prop:checked=move || shell_on.get() on:change=toggle_shell />
                    <span>{move || t().shell_label()}</span>
                </label>
                {move || shell_msg.get().map(|m| match m {
                    ShellMsg::Added => view! { <p class="muted small">{t().shell_added()}</p> }.into_any(),
                    ShellMsg::Removed => view! { <p class="muted small">{t().shell_removed()}</p> }.into_any(),
                    ShellMsg::Failed(e) => view! { <p class="banner ko">{t().error(&e)}</p> }.into_any(),
                })}
            </footer>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustchk_core::Hashes;

    #[test]
    fn groups_fingerprints_by_four() {
        assert_eq!(group_fingerprint("3FC40C125C34EB64"), "3FC4 0C12 5C34 EB64");
        assert_eq!(group_fingerprint("ABCDEF"), "ABCD EF");
        assert_eq!(group_fingerprint(""), "");
    }

    #[test]
    fn verdict_follows_expected_text() {
        let hashes = Hashes { md5: "9".repeat(32), ..Default::default() };
        let report = FileReport {
            path: String::new(),
            name: String::new(),
            size: 0,
            elapsed_ms: 0,
            hashes,
        };
        assert_eq!(verdict_for(None, &parse_expected("")), Verdict::Pending);
        assert_eq!(verdict_for(Some(&report), &parse_expected("")), Verdict::NothingToCompare);
        assert_eq!(verdict_for(Some(&report), &parse_expected("zz")), Verdict::Invalid);
        assert_eq!(verdict_for(Some(&report), &parse_expected(&"9".repeat(32))), Verdict::Match(Algo::Md5));
        assert_eq!(verdict_for(Some(&report), &parse_expected(&"8".repeat(32))), Verdict::Mismatch(Algo::Md5));
    }
}
