(function () {
  'use strict';
  const Filter = window.ProxykingFilters;
  const $ = id => document.getElementById(id);
  const STORAGE_KEY = 'proxyking.savedFilters.v1';
  let groups = Filter.normalizeGroups();
  let mode = 'both';
  let onChange = () => {};

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function rowCount() { return groups.reduce((total, group) => total + group.length, 0); }
  function activeCount() { return groups.flat().filter(Filter.isComplete).filter(condition => !Filter.validate(condition)).length; }
  function savedFilters() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch { return {}; }
  }
  function writeSavedFilters(value) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(value)); return true; } catch { return false; }
  }

  function keyOptions(select, selected) {
    let currentGroup = '';
    for (const field of Filter.FIELD_DEFINITIONS) {
      if (field.group !== currentGroup) {
        currentGroup = field.group;
        select.append(document.createElement('optgroup'));
        select.lastChild.label = currentGroup;
      }
      const option = element('option', '', field.label);
      option.value = field.key; option.selected = field.key === selected;
      select.lastChild.append(option);
    }
  }

  function operatorOptions(select, condition) {
    for (const [value, label] of Filter.operatorsFor(condition.key)) {
      const option = element('option', '', label);
      option.value = value; option.selected = value === condition.operator;
      select.append(option);
    }
  }

  function valueControl(condition) {
    const choices = Filter.choicesFor(condition.key);
    let control;
    if (choices) {
      control = element('select', 'filter-value');
      for (const choice of choices) {
        const option = element('option', '', choice);
        option.value = choice; option.selected = choice.toLowerCase() === String(condition.value).toLowerCase();
        control.append(option);
      }
      if (!condition.value) condition.value = choices[0];
    } else {
      control = element('input', 'filter-value');
      control.type = Filter.FIELD_DEFINITIONS.find(field => field.key === condition.key)?.type === 'number' ? 'number' : 'text';
      control.placeholder = condition.operator === 'regex' ? 'Regular expression' : 'Value';
      control.value = condition.value;
    }
    control.hidden = ['exists', 'notExists'].includes(condition.operator);
    control.setAttribute('aria-label', 'Filter value');
    control.addEventListener('input', () => { condition.value = control.value; update(false); });
    control.addEventListener('change', () => { condition.value = control.value; update(false); });
    return control;
  }

  function addCondition(groupIndex, rowIndex, join) {
    if (rowCount() >= Filter.MAX_ROWS) return;
    const condition = { key: 'url', operator: 'contains', value: '' };
    if (join === 'AND') groups[groupIndex].splice(rowIndex + 1, 0, condition);
    else groups.splice(groupIndex + 1, 0, [condition]);
    update(true);
  }

  function removeCondition(groupIndex, rowIndex) {
    groups[groupIndex].splice(rowIndex, 1);
    if (!groups[groupIndex].length) groups.splice(groupIndex, 1);
    if (!groups.length) groups = Filter.normalizeGroups();
    update(true);
  }

  function renderRows() {
    const container = $('advancedFilterGroups');
    container.replaceChildren();
    const atLimit = rowCount() >= Filter.MAX_ROWS;
    groups.forEach((group, groupIndex) => {
      if (groupIndex) container.append(element('div', 'filter-or-divider', 'OR'));
      const card = element('div', 'filter-group');
      group.forEach((condition, rowIndex) => {
        if (rowIndex) card.append(element('div', 'filter-and-divider', 'AND'));
        const wrapper = element('div', 'filter-row-wrap');
        const row = element('div', 'filter-row');
        const key = element('select', 'filter-key');
        keyOptions(key, condition.key);
        const operator = element('select', 'filter-operator');
        operatorOptions(operator, condition);
        const value = valueControl(condition);
        const remove = element('button', 'filter-remove', '−');
        remove.type = 'button'; remove.title = 'Remove condition'; remove.setAttribute('aria-label', 'Remove condition');
        const and = element('button', 'filter-add and', 'AND');
        and.type = 'button'; and.disabled = atLimit; and.title = atLimit ? 'Maximum 10 conditions' : 'Add required condition';
        const or = element('button', 'filter-add or', 'OR');
        or.type = 'button'; or.disabled = atLimit; or.title = atLimit ? 'Maximum 10 conditions' : 'Start alternative group';
        key.addEventListener('change', () => {
          condition.key = key.value;
          condition.operator = Filter.operatorsFor(condition.key)[0][0];
          condition.value = Filter.choicesFor(condition.key)?.[0] || '';
          update(true);
        });
        operator.addEventListener('change', () => { condition.operator = operator.value; update(true); });
        remove.addEventListener('click', () => removeCondition(groupIndex, rowIndex));
        and.addEventListener('click', () => addCondition(groupIndex, rowIndex, 'AND'));
        or.addEventListener('click', () => addCondition(groupIndex, rowIndex, 'OR'));
        row.append(key, operator, value, remove, and, or);
        wrapper.append(row);
        const error = Filter.validate(condition);
        if (error && (condition.value || ['exists', 'notExists'].includes(condition.operator))) wrapper.append(element('p', 'filter-error', error));
        card.append(wrapper);
      });
      container.append(card);
    });
  }

  function update(rebuild) {
    if (rebuild) renderRows();
    const active = activeCount();
    $('advancedFilterBadge').textContent = String(active);
    $('advancedFilterBadge').hidden = active === 0;
    $('advancedFilterToggle').classList.toggle('active', active > 0);
    $('advancedFilterCount').textContent = `${rowCount()} of ${Filter.MAX_ROWS} conditions`;
    onChange();
  }

  function renderPresets(selected = '') {
    const select = $('savedFilterSelect');
    select.replaceChildren(element('option', '', 'Choose a preset…'));
    select.firstChild.value = '';
    for (const name of Object.keys(savedFilters()).sort((a, b) => a.localeCompare(b))) {
      const option = element('option', '', name); option.value = name; option.selected = name === selected; select.append(option);
    }
    $('deleteSavedFilter').disabled = !select.value;
  }

  function initialize(callback) {
    onChange = callback || onChange;
    renderRows(); renderPresets(); update(false);
    $('advancedFilterToggle').addEventListener('click', () => {
      const open = $('advancedFilterPanel').hidden;
      $('advancedFilterPanel').hidden = !open;
      $('advancedFilterToggle').setAttribute('aria-expanded', String(open));
    });
    $('closeAdvancedFilter').addEventListener('click', () => {
      $('advancedFilterPanel').hidden = true;
      $('advancedFilterToggle').setAttribute('aria-expanded', 'false');
    });
    $('advancedFilterMode').addEventListener('change', () => { mode = $('advancedFilterMode').value; update(false); });
    $('clearAdvancedFilters').addEventListener('click', () => { groups = Filter.normalizeGroups(); $('savedFilterSelect').value = ''; $('savedFilterName').value = ''; update(true); });
    $('savedFilterSelect').addEventListener('change', () => {
      const preset = savedFilters()[$('savedFilterSelect').value];
      $('deleteSavedFilter').disabled = !$('savedFilterSelect').value;
      if (!preset) return;
      groups = Filter.normalizeGroups(preset.groups); mode = ['filter', 'highlight', 'both'].includes(preset.mode) ? preset.mode : 'both';
      $('advancedFilterMode').value = mode; $('savedFilterName').value = $('savedFilterSelect').value; update(true);
    });
    $('saveAdvancedFilter').addEventListener('click', () => {
      const name = $('savedFilterName').value.trim();
      if (!name) { $('savedFilterName').focus(); return; }
      const presets = savedFilters(); presets[name] = { groups, mode };
      if (writeSavedFilters(presets)) renderPresets(name);
    });
    $('deleteSavedFilter').addEventListener('click', () => {
      const name = $('savedFilterSelect').value; if (!name) return;
      const presets = savedFilters(); delete presets[name]; writeSavedFilters(presets);
      $('savedFilterName').value = ''; renderPresets();
    });
  }

  window.ProxykingFilterUI = {
    initialize,
    matches: record => Filter.matches(record, groups),
    isFiltering: () => activeCount() > 0 && (mode === 'filter' || mode === 'both'),
    isHighlighting: () => activeCount() > 0 && (mode === 'highlight' || mode === 'both'),
    matchers: (side, view) => Filter.highlightMatchers(groups, side, view),
    activeCount
  };
})();
