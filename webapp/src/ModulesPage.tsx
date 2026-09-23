import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { request } from './api'

type Parameter = { name: string; value_type: 'string' | 'integer' | 'enum'; allowed_sources: ('input' | 'literal')[]; enum_values: string[] | null; minimum: number | null; maximum: number | null; default_literal: string | number | null }
type Capability = { capability: string; platforms: string[]; minimum_agent_version: string; feature_flag: string; parameters: Parameter[] }
type Binding = { kind: 'input'; name: string } | { kind: 'literal'; value: string | number }
type Input = { name: string; value_type: 'string' | 'integer' }
type Step = { step_id: string; capability: string; parameters: Record<string, Binding> }
type Recipe = { schema_version: 'endpoint_recipe_module_v1'; module_key: string; supported_platforms: string[]; inputs: Input[]; steps: Step[] }
type Version = { version: string; state: string; created_at: string }
type Module = { module_key: string; display_name: string; versions: Version[] }
type Validation = { status: string; error_codes: string[]; warning_codes: string[]; validator_version: string; completed_at: string }
type Lab = { platform: string; status: string; operation_id: string; device_id: string; tested_at: string }
type VersionDetail = { id: string; module_key: string; display_name: string; version: string; state: string; recipe: Recipe; validations: Validation[]; labs: Lab[] }
type Device = { id: string; display_name: string }
type Operation = { data: { status: string }; module_detail: { steps: { sequence: number; capability: string; status: string; error_code: string | null; safe_result: unknown }[] } | null }

const stateLabels: Record<string, string> = { draft: 'Черновик', validation_failed: 'Ошибка проверки', validated: 'Проверен', lab_accepted: 'Испытания приняты', published: 'Опубликован', deprecated: 'Устарел', revoked: 'Отозван' }
const errorLabels: Record<string, string> = { recipe_contract_invalid: 'Неверный формат рецепта', recipe_catalog_invalid: 'Рецепт не соответствует каталогу' }
const dateText = (value: string) => new Intl.DateTimeFormat('ru-RU', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
const emptyRecipe = (): Recipe => ({ schema_version: 'endpoint_recipe_module_v1', module_key: '', supported_platforms: ['linux_amd64'], inputs: [], steps: [] })
const initialBinding = (parameter: Parameter): Binding => parameter.allowed_sources.includes('input') ? { kind: 'input', name: '' } : { kind: 'literal', value: parameter.default_literal ?? (parameter.value_type === 'integer' ? parameter.minimum ?? 0 : parameter.enum_values?.[0] ?? '') }
const message = (reason: unknown) => reason instanceof Error ? reason.message : 'Не удалось выполнить действие'

function InputValues({ inputs, values, onChange }: { inputs: Input[]; values: Record<string, string>; onChange: (values: Record<string, string>) => void }) {
  return <div className="filters">{inputs.map(input => <label key={input.name}>{input.name} ({input.value_type === 'integer' ? 'число' : 'строка'})<input type={input.value_type === 'integer' ? 'number' : 'text'} required value={values[input.name] ?? ''} onChange={event => onChange({ ...values, [input.name]: event.target.value })} /></label>)}</div>
}

export function ModulesPage() {
  const [catalog, setCatalog] = useState<Capability[]>([])
  const [modules, setModules] = useState<Module[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [detail, setDetail] = useState<VersionDetail | null>(null)
  const [draftName, setDraftName] = useState('')
  const [draftVersion, setDraftVersion] = useState('1.0.0')
  const [recipe, setRecipe] = useState<Recipe>(emptyRecipe)
  const [devices, setDevices] = useState<Device[]>([])
  const [labDevice, setLabDevice] = useState('')
  const [labValues, setLabValues] = useState<Record<string, string>>({})
  const [operationId, setOperationId] = useState('')
  const [operation, setOperation] = useState<Operation | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [revision, setRevision] = useState(0)

  useEffect(() => {
    let active = true
    Promise.all([
      request<{ data: { items: Capability[] } }>('/api/admin/console/module-capabilities'),
      request<{ data: Module[]; total: number }>(`/api/admin/console/modules?limit=50&offset=${offset}`),
    ]).then(([capabilities, listing]) => { if (active) { setCatalog(capabilities.data.items); setModules(listing.data); setTotal(listing.total); setError('') } })
      .catch(reason => { if (active) setError(message(reason)) })
    return () => { active = false }
  }, [revision, offset])
  useEffect(() => {
    if (!detail) return
    let active = true
    request<{ data: VersionDetail }>(`/api/admin/console/modules/${encodeURIComponent(detail.module_key)}/versions/${encodeURIComponent(detail.version)}`)
      .then(value => { if (active) setDetail(value.data) })
      .catch(reason => { if (active) setError(message(reason)) })
    return () => { active = false }
  }, [revision, detail?.module_key, detail?.version])
  useEffect(() => {
    if (!detail || detail.state !== 'validated') { setDevices([]); return }
    let active = true
    request<{ data: Device[] }>(`/api/admin/console/modules/${detail.module_key}/versions/${detail.version}/lab-devices`)
      .then(value => { if (active) setDevices(value.data) })
      .catch(reason => { if (active) setError(message(reason)) })
    return () => { active = false }
  }, [revision, detail?.module_key, detail?.version, detail?.state])
  useEffect(() => {
    if (!operationId) return
    let active = true
    const load = () => request<Operation>(`/api/admin/operations/${operationId}`)
      .then(value => { if (active) setOperation(value) })
      .catch(reason => { if (active) setError(message(reason)) })
    void load()
    const timer = window.setInterval(load, 3000)
    return () => { active = false; window.clearInterval(timer) }
  }, [operationId])

  function changeCapability(index: number, capability: Capability) {
    const steps = [...recipe.steps]
    steps[index] = { ...steps[index], capability: capability.capability, parameters: Object.fromEntries(capability.parameters.map(parameter => [parameter.name, initialBinding(parameter)])) }
    setRecipe({ ...recipe, steps })
  }
  function setBinding(index: number, name: string, binding: Binding) {
    const steps = [...recipe.steps]
    steps[index] = { ...steps[index], parameters: { ...steps[index].parameters, [name]: binding } }
    setRecipe({ ...recipe, steps })
  }
  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try {
      const result = await request<{ data: { module_key: string; version: string } }>('/api/admin/console/modules/versions', { method: 'POST', body: JSON.stringify({ schema_version: 'module_version_create_v1', display_name: draftName, version: draftVersion, recipe }) })
      const value = await request<{ data: VersionDetail }>(`/api/admin/console/modules/${result.data.module_key}/versions/${result.data.version}`)
      setDetail(value.data); setRevision(current => current + 1); setNotice('Черновик создан. Запустите проверку.')
    } catch (reason) { setError(message(reason)) } finally { setBusy(false) }
  }
  async function transition(action: string, label: string) {
    if (!detail) return
    if (['publish', 'deprecate'].includes(action) && !window.confirm(`${label} ${detail.module_key}@${detail.version}?`)) return
    setBusy(true); setError(''); setNotice('')
    try {
      await request(`/api/admin/console/modules/${detail.module_key}/versions/${detail.version}/${action}`, { method: 'POST' })
      setNotice(`${label}: выполнено`); setRevision(current => current + 1)
    } catch (reason) { setError(message(reason)) } finally { setBusy(false) }
  }
  async function startLab(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!detail) return
    setBusy(true); setError(''); setNotice('')
    try {
      const inputs = Object.fromEntries(detail.recipe.inputs.map(input => [input.name, input.value_type === 'integer' ? Number(labValues[input.name]) : labValues[input.name]]))
      const result = await request<{ data: { operation_id: string } }>(`/api/admin/console/modules/${detail.module_key}/versions/${detail.version}/lab-operations/${labDevice}`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ schema_version: 'endpoint_module_lab_operation_create_v1', inputs }) })
      setOperationId(result.data.operation_id); setOperation(null); setNotice('Лабораторная операция создана')
    } catch (reason) { setError(message(reason)) } finally { setBusy(false) }
  }
  async function recordEvidence() {
    if (!detail || !operationId) return
    setBusy(true); setError('')
    try {
      await request(`/api/admin/console/modules/${detail.module_key}/versions/${detail.version}/lab-evidence/${operationId}`, { method: 'POST' })
      setNotice('Результат испытания сохранён из завершённой операции'); setRevision(current => current + 1)
    } catch (reason) { setError(message(reason)) } finally { setBusy(false) }
  }
  return <>
    <div className="page-heading"><div><p className="eyebrow">MODULE WORKBENCH</p><h1>Модули</h1><p className="muted">Последовательные рецепты из разрешённых возможностей Endpoint</p></div><button onClick={() => setRevision(current => current + 1)}>Обновить</button></div>
    {error && <section className="panel error" role="alert">{error}</section>}{notice && <section className="panel" role="status">{notice}</section>}
    <section className="panel"><h2>Каталог возможностей</h2>{catalog.length ? <ul>{catalog.map(item => <li key={item.capability}><strong>{item.capability}</strong> · {item.platforms.join(', ')} · Agent ≥ {item.minimum_agent_version} · {item.feature_flag}</li>)}</ul> : <p>Каталог не загружен.</p>}</section>
    <section className="panel table-panel"><div className="table-top"><h2>Модули и версии</h2><span>{total} всего</span></div>{modules.length ? <div className="table-scroll"><table><thead><tr><th>Модуль</th><th>Версия</th><th>Состояние</th><th></th></tr></thead><tbody>{modules.flatMap(item => item.versions.map(version => <tr key={`${item.module_key}-${version.version}`}><td>{item.display_name}<small>{item.module_key}</small></td><td>{version.version}</td><td>{stateLabels[version.state] ?? version.state}</td><td><button onClick={async () => { try { const value = await request<{ data: VersionDetail }>(`/api/admin/console/modules/${item.module_key}/versions/${version.version}`); setDetail(value.data); setOperationId('') } catch (reason) { setError(message(reason)) } }}>Открыть</button></td></tr>))}</tbody></table></div> : <p className="empty-text">Модулей пока нет.</p>}<div className="pagination"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Назад</button><span>{Math.min(offset + 50, total)} из {total}</span><button disabled={offset + 50 >= total} onClick={() => setOffset(offset + 50)}>Далее</button></div></section>
    {detail && <section className="panel"><button onClick={() => setDetail(null)}>Закрыть версию</button><h2>{detail.display_name} · {detail.version}</h2><p>{detail.module_key} · {stateLabels[detail.state] ?? detail.state}</p><p>Платформы: {detail.recipe.supported_platforms.join(', ')}</p><ol>{detail.recipe.steps.map(step => <li key={step.step_id}>{step.step_id}: {step.capability} · {Object.entries(step.parameters).map(([name, binding]) => `${name}=${binding.kind === 'input' ? `input.${binding.name}` : String(binding.value)}`).join(', ')}</li>)}</ol><div className="actions"><button disabled={busy || !['draft', 'validation_failed'].includes(detail.state)} onClick={() => transition('validate', 'Проверка')}>Проверить модуль</button><button disabled={busy || detail.state !== 'validated'} onClick={() => transition('accept-labs', 'Принятие испытаний')}>Принять испытания</button><button disabled={busy || detail.state !== 'lab_accepted'} onClick={() => transition('publish', 'Публикация')}>Опубликовать</button><button disabled={busy || detail.state !== 'published'} onClick={() => transition('deprecate', 'Устаревание')}>Пометить устаревшим</button></div><h3>Проверки</h3>{detail.validations.length ? <ul>{detail.validations.map((item, index) => <li key={index}>{dateText(item.completed_at)} · {item.status === 'succeeded' ? 'Успешно' : 'Ошибка'} · {item.validator_version}{item.error_codes.map(code => <span key={code}> · {errorLabels[code] ?? code} ({code})</span>)}{item.warning_codes.map(code => <span key={code}> · Предупреждение: {code}</span>)}</li>)}</ul> : <p>Проверок ещё нет.</p>}
      <h3>Лабораторные испытания</h3>{detail.labs.length ? <ul>{detail.labs.map((item, index) => <li key={index}>{item.platform} · {item.status} · {dateText(item.tested_at)} · <Link to={`/admin/operations?device_id=${item.device_id}`}>Операция {item.operation_id}</Link></li>)}</ul> : <p>Испытаний ещё нет.</p>}
      {detail.state === 'validated' && <form onSubmit={startLab}><h3>Запустить испытание</h3><label>Совместимое устройство<select required value={labDevice} onChange={event => setLabDevice(event.target.value)}><option value="">Выберите устройство</option>{devices.map(item => <option key={item.id} value={item.id}>{item.display_name}</option>)}</select></label>{!devices.length && <p className="muted">Совместимых подключённых устройств сейчас нет.</p>}<InputValues inputs={detail.recipe.inputs} values={labValues} onChange={setLabValues} /><button disabled={busy || !labDevice} type="submit">Запустить испытание</button></form>}
      {operationId && <div className="panel"><h3>Испытание {operationId}</h3><p>Состояние: {operation?.data.status ?? 'Загрузка…'}</p>{operation?.module_detail && <ol>{operation.module_detail.steps.map(step => <li key={step.sequence}>{step.capability} · {step.status}{step.error_code && ` · ${step.error_code}`}{step.safe_result != null && <pre className="safe-log">{JSON.stringify(step.safe_result, null, 2)}</pre>}</li>)}</ol>}{operation?.data.status === 'succeeded' && <button disabled={busy} onClick={recordEvidence}>Сохранить подтверждение испытания</button>}</div>}
    </section>}
    <form className="panel" onSubmit={create}><h2>Новый черновик</h2><div className="filters"><label>Название<input required maxLength={128} value={draftName} onChange={event => setDraftName(event.target.value)} /></label><label>Module key<input required pattern="[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+" placeholder="network.basic.check" value={recipe.module_key} onChange={event => setRecipe({ ...recipe, module_key: event.target.value })} /></label><label>Версия<input required pattern="[0-9]+\.[0-9]+\.[0-9]+" value={draftVersion} onChange={event => setDraftVersion(event.target.value)} /></label></div><fieldset><legend>Платформы</legend>{['linux_amd64', 'windows_amd64'].map(platform => <label key={platform}><input type="checkbox" checked={recipe.supported_platforms.includes(platform)} onChange={event => setRecipe({ ...recipe, supported_platforms: event.target.checked ? [...recipe.supported_platforms, platform] : recipe.supported_platforms.filter(value => value !== platform) })} />{platform}</label>)}</fieldset>
      <h3>Входные параметры ({recipe.inputs.length}/8)</h3>{recipe.inputs.map((input, index) => <div className="filters" key={index}><label>Имя<input required pattern="[a-z][a-z0-9_]*" value={input.name} onChange={event => setRecipe({ ...recipe, inputs: recipe.inputs.map((value, at) => at === index ? { ...value, name: event.target.value } : value) })} /></label><label>Тип<select value={input.value_type} onChange={event => setRecipe({ ...recipe, inputs: recipe.inputs.map((value, at) => at === index ? { ...value, value_type: event.target.value as Input['value_type'] } : value) })}><option value="string">Строка</option><option value="integer">Целое число</option></select></label><button type="button" onClick={() => setRecipe({ ...recipe, inputs: recipe.inputs.filter((_, at) => at !== index) })}>Удалить</button></div>)}<button type="button" disabled={recipe.inputs.length >= 8} onClick={() => setRecipe({ ...recipe, inputs: [...recipe.inputs, { name: '', value_type: 'string' }] })}>Добавить вход</button>
      <h3>Шаги ({recipe.steps.length}/8)</h3>{recipe.steps.map((step, index) => { const capability = catalog.find(item => item.capability === step.capability); return <fieldset key={index}><legend>Шаг {index + 1}</legend><div className="filters"><label>ID шага<input required pattern="[a-z][a-z0-9_]*" value={step.step_id} onChange={event => setRecipe({ ...recipe, steps: recipe.steps.map((value, at) => at === index ? { ...value, step_id: event.target.value } : value) })} /></label><label>Возможность<select value={step.capability} onChange={event => { const item = catalog.find(value => value.capability === event.target.value); if (item) changeCapability(index, item) }}>{catalog.map(item => <option key={item.capability} value={item.capability}>{item.capability}</option>)}</select></label><button type="button" onClick={() => setRecipe({ ...recipe, steps: recipe.steps.filter((_, at) => at !== index) })}>Удалить шаг</button></div>{capability?.parameters.map(parameter => { const binding = step.parameters[parameter.name]; return <div className="filters" key={parameter.name}><label>{parameter.name}<select value={binding?.kind ?? 'input'} onChange={event => setBinding(index, parameter.name, event.target.value === 'input' ? { kind: 'input', name: '' } : { kind: 'literal', value: parameter.default_literal ?? (parameter.value_type === 'integer' ? parameter.minimum ?? 0 : parameter.enum_values?.[0] ?? '') })}>{parameter.allowed_sources.map(source => <option key={source} value={source}>{source === 'input' ? 'Входной параметр' : 'Значение'}</option>)}</select></label>{binding?.kind === 'input' ? <label>Вход<select required value={binding.name} onChange={event => setBinding(index, parameter.name, { kind: 'input', name: event.target.value })}><option value="">Выберите</option>{recipe.inputs.filter(item => parameter.value_type === 'integer' ? item.value_type === 'integer' : item.value_type === 'string').map(item => <option key={item.name} value={item.name}>{item.name}</option>)}</select></label> : <label>Значение{parameter.enum_values ? <select value={String(binding?.value ?? '')} onChange={event => setBinding(index, parameter.name, { kind: 'literal', value: event.target.value })}>{parameter.enum_values.map(value => <option key={value} value={value}>{value}</option>)}</select> : <input required type={parameter.value_type === 'integer' ? 'number' : 'text'} min={parameter.minimum ?? undefined} max={parameter.maximum ?? undefined} value={binding?.value ?? ''} onChange={event => setBinding(index, parameter.name, { kind: 'literal', value: parameter.value_type === 'integer' ? Number(event.target.value) : event.target.value })} />}</label>}</div> })}</fieldset> })}<button type="button" disabled={recipe.steps.length >= 8 || !catalog.length} onClick={() => { const capability = catalog[0]; setRecipe({ ...recipe, steps: [...recipe.steps, { step_id: `step${recipe.steps.length + 1}`, capability: capability.capability, parameters: Object.fromEntries(capability.parameters.map(parameter => [parameter.name, initialBinding(parameter)])) }] }) }}>Добавить шаг</button><p className="muted">Рецепт выполняется последовательно. Ограничение: 8 входов и 8 шагов.</p><button className="primary-button" disabled={busy || recipe.steps.length === 0 || recipe.supported_platforms.length === 0} type="submit">Создать черновик</button>
    </form>
  </>
}

type PublishedModule = { module_key: string; display_name: string; version: string; compatible: boolean; reason: string | null; inputs: Input[] }
export function DeviceModules({ deviceId }: { deviceId: string }) {
  const [modules, setModules] = useState<PublishedModule[]>([])
  const [values, setValues] = useState<Record<string, Record<string, string>>>({})
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { let active = true; request<{ data: PublishedModule[] }>(`/api/admin/console/devices/${deviceId}/modules`).then(value => { if (active) setModules(value.data) }).catch(reason => { if (active) setError(message(reason)) }); return () => { active = false } }, [deviceId])
  async function run(event: FormEvent<HTMLFormElement>, item: PublishedModule) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('')
    try {
      const inputs = Object.fromEntries(item.inputs.map(input => [input.name, input.value_type === 'integer' ? Number(values[item.module_key]?.[input.name]) : values[item.module_key]?.[input.name]]))
      const result = await request<{ data: { operation_id: string } }>(`/api/admin/console/devices/${deviceId}/module-operations`, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ schema_version: 'endpoint_module_operation_create_v1', module_key: item.module_key, version: item.version, inputs }) })
      setNotice(`Операция ${result.data.operation_id} создана. Результат доступен в журнале операций.`)
    } catch (reason) { setError(message(reason)) } finally { setBusy(false) }
  }
  return <section className="panel"><h2>Опубликованные модули</h2>{error && <p className="error" role="alert">{error}</p>}{notice && <p role="status">{notice}</p>}{modules.length ? modules.map(item => <form key={`${item.module_key}-${item.version}`} className="panel" onSubmit={event => run(event, item)}><h3>{item.display_name} · {item.version}</h3><p className="muted">{item.module_key}</p>{item.compatible ? <><InputValues inputs={item.inputs} values={values[item.module_key] ?? {}} onChange={next => setValues({ ...values, [item.module_key]: next })} /><button disabled={busy}>Запустить модуль</button></> : <p>Недоступен: {item.reason ?? 'Устройство несовместимо'}</p>}</form>) : <p>Опубликованных модулей нет.</p>}</section>
}
