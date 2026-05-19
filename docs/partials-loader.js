async function injectPartials() {
  const elements = document.querySelectorAll('[data-include]');
  await Promise.all(
    [...elements].map(async (element) => {
      const target = element.getAttribute('data-include');
      const response = await fetch(target);
      if (!response.ok) {
        throw new Error(`Could not load partial ${target}`);
      }
      element.innerHTML = await response.text();
    })
  );
}

injectPartials().catch((error) => {
  console.error(error.message);
});
