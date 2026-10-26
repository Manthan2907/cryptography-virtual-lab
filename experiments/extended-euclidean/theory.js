/* ==========================================================================
   Extended Euclidean Algorithm — Theory tab interactions
   Scoped to #theory. Progressive enhancement: with JavaScript disabled the
   static theory text (and every stepper step) is still fully readable.
   ========================================================================== */
(() => {
	'use strict';

	function start() {
		const theory = document.getElementById('theory');
		if (!theory) {
			return;
		}

		/* ---- Progressive steppers ------------------------------------- */
		function initStepper(root) {
			const steps = Array.from(root.querySelectorAll('[data-step]'));
			if (!steps.length) {
				return;
			}

			const prevBtn = root.querySelector('[data-step-prev]');
			const nextBtn = root.querySelector('[data-step-next]');
			const progress = root.querySelector('[data-step-progress]');
			const conclusion = root.querySelector('[data-step-conclusion]');
			const unit = root.dataset.stepUnit || 'Step';
			const total = steps.length;
			let index = 0;

			function render() {
				steps.forEach((step, i) => {
					const revealed = i <= index;
					step.hidden = !revealed;
					step.classList.toggle('is-done', revealed && i < index);
					step.classList.toggle('is-current', i === index);
				});

				if (progress) {
					progress.textContent = unit + ' ' + (index + 1) + ' of ' + total;
				}
				if (prevBtn) {
					prevBtn.disabled = index === 0;
				}
				if (nextBtn) {
					nextBtn.disabled = index === total - 1;
				}
				if (conclusion) {
					conclusion.hidden = index !== total - 1;
				}
			}

			function go(delta) {
				const next = Math.min(total - 1, Math.max(0, index + delta));
				if (next === index) {
					return;
				}
				index = next;
				render();
			}

			if (prevBtn) {
				prevBtn.addEventListener('click', () => go(-1));
			}
			if (nextBtn) {
				nextBtn.addEventListener('click', () => go(1));
			}

			root.addEventListener('keydown', (event) => {
				if (event.key === 'ArrowLeft') {
					event.preventDefault();
					go(-1);
				} else if (event.key === 'ArrowRight') {
					event.preventDefault();
					go(1);
				}
			});

			render();
		}

		/* ---- Bezout verification widget ------------------------------- */
		function initVerify(root) {
			const a = Number(root.dataset.a);
			const b = Number(root.dataset.b);
			const gcd = Number(root.dataset.gcd);
			const output = root.querySelector('[data-verify-output]');
			if (!output) {
				return;
			}

			function signed(n) {
				return n < 0 ? '(' + fmt(n) + ')' : String(n);
			}

			function fmt(n) {
				return String(n).replace('-', '\u2212');
			}

			root.querySelectorAll('[data-coeffs]').forEach((btn) => {
				btn.addEventListener('click', () => {
					const parts = btn.dataset.coeffs.split(',');
					const x = Number(parts[0]);
					const y = Number(parts[1]);
					const ax = a * x;
					const by = b * y;
					const sum = ax + by;
					const ok = sum === gcd;

					const line = document.createElement('p');
					line.className = 'verify-line';
					line.textContent = a + ' \u00D7 ' + signed(x) + ' + ' + b + ' \u00D7 ' + signed(y) +
						' = ' + fmt(ax) + ' + ' + fmt(by) + ' = ' + fmt(sum);

					const verdict = document.createElement('p');
					verdict.className = 'verify-verdict ' + (ok ? 'is-ok' : 'is-bad');
					verdict.textContent = ok
						? '\u2713 Equals gcd(' + a + ', ' + b + ') = ' + gcd + ' \u2014 B\u00E9zout\u2019s identity holds.'
						: '\u2717 Equals ' + fmt(sum) + ', not the GCD ' + gcd + ' \u2014 this pair does not satisfy B\u00E9zout\u2019s identity.';

					output.replaceChildren(line, verdict);
					output.hidden = false;
				});
			});
		}

		/* ---- Modular inverse checks ----------------------------------- */
		function initModChecks(scope) {
			scope.querySelectorAll('[data-modcheck]').forEach((btn) => {
				btn.addEventListener('click', () => {
					const a = Number(btn.dataset.a);
					const m = Number(btn.dataset.m);
					const x = Number(btn.dataset.x);
					const product = a * x;
					const remainder = ((product % m) + m) % m;
					const ok = remainder === 1;
					const output = btn.parentElement
						? btn.parentElement.querySelector('[data-mod-output]')
						: null;
					if (!output) {
						return;
					}

					const line = document.createElement('p');
					line.className = 'verify-line';
					line.textContent = a + ' \u00D7 ' + x + ' = ' + product +
						' \u2261 ' + remainder + ' (mod ' + m + ')';

					const verdict = document.createElement('p');
					verdict.className = 'verify-verdict ' + (ok ? 'is-ok' : 'is-bad');
					verdict.textContent = (ok ? '\u2713 ' : '\u2717 ') + (btn.dataset.message || '');

					output.replaceChildren(line, verdict);
					output.hidden = false;
				});
			});
		}

		/* ---- Quick knowledge checks ----------------------------------- */
		function initCheck(root) {
			const feedback = root.querySelector('[data-check-feedback]');
			const options = Array.from(root.querySelectorAll('[data-correct]'));
			if (!feedback || !options.length) {
				return;
			}

			const explanation = root.dataset.explanation || '';

			options.forEach((option) => {
				option.addEventListener('click', () => {
					if (root.dataset.answered === 'true') {
						return;
					}
					root.dataset.answered = 'true';

					const isCorrect = option.dataset.correct === 'true';

					options.forEach((item) => {
						item.disabled = true;
						if (item.dataset.correct === 'true') {
							item.classList.add('is-correct');
						}
					});
					if (!isCorrect) {
						option.classList.add('is-incorrect');
					}

					feedback.hidden = false;
					feedback.classList.add(isCorrect ? 'is-correct' : 'is-incorrect');
					feedback.textContent = (isCorrect ? '\u2713 Correct. ' : '\u2717 Not quite. ') + explanation;
				});
			});
		}

		theory.querySelectorAll('[data-theory-stepper]').forEach(initStepper);
		theory.querySelectorAll('[data-verify]').forEach(initVerify);
		theory.querySelectorAll('[data-check]').forEach(initCheck);
		initModChecks(theory);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', start);
	} else {
		start();
	}
})();
